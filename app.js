const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
require('dotenv').config();

const app = express();

// Middleware
app.use('/interactions', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(express.static('public'));

// Configuration from environment variables
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const PUBLIC_KEY = process.env.PUBLIC_KEY;
const REDIRECT_URI = process.env.REDIRECT_URI || (process.env.NODE_ENV === 'production' 
    ? 'https://your-app-name.up.railway.app/callback' 
    : 'http://localhost:3000/callback');
const PORT = process.env.PORT || 3000;

// Store user tokens (in production, use a database)
const userTokens = new Map();

// Validate required environment variables
function validateConfig() {
    const required = ['CLIENT_ID', 'CLIENT_SECRET', 'PUBLIC_KEY'];
    const missing = required.filter(key => !process.env[key]);
    
    if (missing.length > 0) {
        console.error(`❌ Missing required environment variables: ${missing.join(', ')}`);
        console.log(`
Create a .env file with:
CLIENT_ID=your_application_id
CLIENT_SECRET=your_application_secret
PUBLIC_KEY=your_public_key
REDIRECT_URI=http://localhost:3000/callback
        `);
        process.exit(1);
    }
}

// Verify Discord signature for interactions
function verifySignature(rawBody, signature, timestamp) {
    try {
        const body = timestamp + rawBody;
        const hash = crypto
            .createHmac("sha256", PUBLIC_KEY)
            .update(body, 'utf8')
            .digest("hex");
        
        const sigBuffer = Buffer.from(signature, "hex");
        const hashBuffer = Buffer.from(hash, "hex");
        
        return sigBuffer.length === hashBuffer.length && 
               crypto.timingSafeEqual(sigBuffer, hashBuffer);
    } catch (error) {
        console.error('Signature verification error:', error);
        return false;
    }
}

// OAuth2 authorization URL
app.get('/auth', (req, res) => {
    const authUrl = `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=identify%20guilds%20messages.read%20guilds.messages.read`;
    res.redirect(authUrl);
});

// OAuth2 callback handler
app.post('/callback', async (req, res) => {
    const { code } = req.body;
    
    if (!code) {
        return res.status(400).json({ error: 'No authorization code provided' });
    }

    try {
        // Exchange code for access token
        const tokenResponse = await axios.post('https://discord.com/api/oauth2/token', 
            new URLSearchParams({
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: REDIRECT_URI
            }), {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );

        const { access_token, refresh_token } = tokenResponse.data;

        // Get user info
        const userResponse = await axios.get('https://discord.com/api/users/@me', {
            headers: {
                'Authorization': `Bearer ${access_token}`
            }
        });

        const userData = userResponse.data;
        
        // Store tokens
        userTokens.set(userData.id, {
            access_token,
            refresh_token,
            user_data: userData
        });

        console.log(`✅ User authorized: ${userData.username}#${userData.discriminator}`);
        
        res.json({
            success: true,
            user: {
                id: userData.id,
                username: userData.username,
                discriminator: userData.discriminator
            }
        });

    } catch (error) {
        console.error('OAuth error:', error.response?.data || error.message);
        res.status(500).json({ error: 'Authorization failed' });
    }
});

// Send message using user's token
async function sendUserMessage(userId, channelId, content) {
    const userToken = userTokens.get(userId);
    if (!userToken) {
        throw new Error('User not authorized');
    }

    try {
        const response = await axios.post(
            `https://discord.com/api/v10/channels/${channelId}/messages`,
            { content },
            {
                headers: {
                    'Authorization': `Bearer ${userToken.access_token}`,
                    'Content-Type': 'application/json'
                }
            }
        );
        return response.data;
    } catch (error) {
        // Try to refresh token if expired
        if (error.response?.status === 401) {
            await refreshUserToken(userId);
            // Retry with new token
            const newToken = userTokens.get(userId);
            const retryResponse = await axios.post(
                `https://discord.com/api/v10/channels/${channelId}/messages`,
                { content },
                {
                    headers: {
                        'Authorization': `Bearer ${newToken.access_token}`,
                        'Content-Type': 'application/json'
                    }
                }
            );
            return retryResponse.data;
        }
        throw error;
    }
}

// Refresh user token
async function refreshUserToken(userId) {
    const userToken = userTokens.get(userId);
    if (!userToken?.refresh_token) {
        throw new Error('No refresh token available');
    }

    try {
        const response = await axios.post('https://discord.com/api/oauth2/token',
            new URLSearchParams({
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                grant_type: 'refresh_token',
                refresh_token: userToken.refresh_token
            }), {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );

        const { access_token, refresh_token } = response.data;
        
        // Update stored tokens
        userTokens.set(userId, {
            ...userToken,
            access_token,
            refresh_token: refresh_token || userToken.refresh_token
        });

        console.log(`🔄 Refreshed token for user ${userId}`);
    } catch (error) {
        console.error('Token refresh failed:', error.response?.data || error.message);
        // Remove invalid token
        userTokens.delete(userId);
        throw error;
    }
}

// Handle Discord interactions
app.post('/interactions', async (req, res) => {
    try {
        const signature = req.headers['x-signature-ed25519'];
        const timestamp = req.headers['x-signature-timestamp'];
        
        if (!signature || !timestamp) {
            return res.status(401).json({ error: 'Missing signature headers' });
        }

        const rawBody = req.body.toString();

        // Verify the request signature
        if (!verifySignature(rawBody, signature, timestamp)) {
            console.error('Invalid signature detected');
            return res.status(401).json({ error: 'Invalid request signature' });
        }

        const interaction = JSON.parse(rawBody);

        // Handle PING (Discord's verification)
        if (interaction.type === 1) {
            return res.json({ type: 1 });
        }

        // Handle APPLICATION_COMMAND
        if (interaction.type === 2) {
            if (interaction.data.name === 'send') {
                const userId = interaction.user?.id || interaction.member?.user?.id;
                const userToken = userTokens.get(userId);

                // Check if user is authorized
                if (!userToken) {
                    return res.json({
                        type: 4,
                        data: {
                            content: '❌ You need to authorize first! Visit: http://localhost:3000/auth',
                            flags: 64 // Ephemeral
                        }
                    });
                }

                const message = interaction.data.options?.find(opt => opt.name === 'message')?.value;
                const count = Math.min(
                    interaction.data.options?.find(opt => opt.name === 'count')?.value || 1,
                    5 // Limit to 5 messages
                );

                if (!message) {
                    return res.json({
                        type: 4,
                        data: {
                            content: '❌ Message content is required!',
                            flags: 64
                        }
                    });
                }

                const channelId = interaction.channel_id;

                try {
                    // Acknowledge the interaction
                    res.json({
                        type: 5, // DEFERRED_CHANNEL_MESSAGE_WITH_SOURCE
                        data: { flags: 64 }
                    });

                    // Send messages as the user
                    for (let i = 0; i < count; i++) {
                        const messageContent = count > 1 
                            ? `${message} (${i + 1}/${count})`
                            : message;
                        
                        await sendUserMessage(userId, channelId, messageContent);
                        
                        if (i < count - 1) {
                            await new Promise(resolve => setTimeout(resolve, 1000));
                        }
                    }

                    // Send follow-up
                    await axios.patch(
                        `https://discord.com/api/v10/webhooks/${CLIENT_ID}/${interaction.token}/messages/@original`,
                        {
                            content: `✅ Successfully sent ${count} message${count > 1 ? 's' : ''} as ${userToken.user_data.username}!`
                        }
                    );

                } catch (error) {
                    console.error('Send message error:', error.response?.data || error.message);
                    
                    try {
                        await axios.patch(
                            `https://discord.com/api/v10/webhooks/${CLIENT_ID}/${interaction.token}/messages/@original`,
                            {
                                content: `❌ Failed to send messages: ${error.response?.data?.message || error.message}`
                            }
                        );
                    } catch (followupError) {
                        console.error('Follow-up error:', followupError);
                    }
                }
                return;
            }

            if (interaction.data.name === 'authorize') {
                return res.json({
                    type: 4,
                    data: {
                        content: `🔗 Click here to authorize: http://localhost:${PORT}/auth`,
                        flags: 64
                    }
                });
            }
        }

        return res.status(400).json({ error: 'Unknown interaction type' });

    } catch (error) {
        console.error('Interaction handler error:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// Register slash commands
async function registerCommands() {
    const commands = [
        {
            name: 'send',
            description: 'Send a message as yourself (requires authorization)',
            options: [
                {
                    type: 3, // STRING
                    name: 'message',
                    description: 'The message to send',
                    required: true,
                    max_length: 2000
                },
                {
                    type: 4, // INTEGER
                    name: 'count',
                    description: 'How many times to send the message (max 5)',
                    required: false,
                    min_value: 1,
                    max_value: 5
                }
            ]
        },
        {
            name: 'authorize',
            description: 'Get authorization link to use the app'
        }
    ];

    try {
        console.log('🔄 Registering slash commands...');
        
        // Note: For External Apps, you might need to register commands differently
        // This registers global commands - you may want guild-specific commands instead
        const response = await axios.put(
            `https://discord.com/api/v10/applications/${CLIENT_ID}/commands`,
            commands,
            {
                headers: {
                    'Authorization': `Bot ${process.env.BOT_TOKEN}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        console.log(`✅ Successfully registered ${response.data.length} slash commands!`);

    } catch (error) {
        console.error('❌ Command registration failed. For External Apps, you may need to register commands through Discord Developer Portal manually.');
        console.log('Commands can be registered manually in Discord Developer Portal > Your App > Slash Commands');
    }
}

// Root endpoint with instructions
app.get('/', (req, res) => {
    res.json({
        message: 'Discord External App Server',
        setup: {
            step1: 'Visit /auth to authorize your Discord account',
            step2: 'Use slash commands in Discord servers',
            step3: 'Messages will be sent as your Discord account'
        },
        endpoints: {
            authorize: '/auth',
            callback: '/callback',
            interactions: '/interactions'
        },
        authorized_users: Array.from(userTokens.keys()).length
    });
});

// Start server
async function startServer() {
    try {
        validateConfig();
        
        app.listen(PORT, () => {
            console.log(`🚀 Discord External App Server running on port ${PORT}`);
            console.log(`🔗 Authorization URL: http://localhost:${PORT}/auth`);
            console.log(`📡 Interactions endpoint: http://localhost:${PORT}/interactions`);
            console.log('');
            console.log('📋 Setup Instructions:');
            console.log('1. Set your Interactions Endpoint URL in Discord Developer Portal to:');
            console.log(`   http://localhost:${PORT}/interactions`);
            console.log('2. Users must visit /auth to authorize before using commands');
            console.log('3. Messages will be sent as the authorized user, not as a bot');
            console.log('');
            console.log('⚠️  Note: This is an External App - it works WITHOUT adding a bot to servers!');
        });

        // Try to register commands (may fail for external apps)
        if (process.env.BOT_TOKEN) {
            await registerCommands();
        }

    } catch (error) {
        console.error('❌ Failed to start server:', error.message);
        process.exit(1);
    }
}

startServer();
