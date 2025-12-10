const TelegramBot = require("node-telegram-bot-api");
const fs = require("fs");
const path = require("path");
const archiver = require("archiver");

const BOT_TOKEN = "8598204496:AAGBC54YH971QBHGKMBiy5U9niKggbEKBCw";
const ADMIN_IDS = [6381012703];
const BASE = path.join(__dirname, "sessionStore");

// Create directory if it doesn't exist
if (!fs.existsSync(BASE)) {
    fs.mkdirSync(BASE, { recursive: true });
}

const bot = new TelegramBot(BOT_TOKEN, { polling: true });

function enc(text) { return Buffer.from(text).toString("base64"); }
function dec(text) { return Buffer.from(text, "base64").toString(); }

function getMiddleName(folderName) {
    const parts = folderName.split("_");
    if (parts.length >= 3) return parts[1];
    return folderName;
}

function extractTimestamp(filename) {
    // Extract numbers from filename (e.g., session_1234567890.txt or 1234567890.txt)
    const match = filename.match(/\d+/);
    return match ? parseInt(match[0]) : Date.now();
}

let folderMap = {};
const userStates = new Map(); // Store user states: chatId -> "waiting_for_token"

// ===================== START =====================
bot.onText(/\/start/, (msg) => {
    bot.sendMessage(msg.chat.id, `👋 Welcome ${msg.from.first_name}!\nUse /session to manage your sessions.`);
});

// ===================== SESSION COMMAND =====================
bot.onText(/\/session/, (msg) => {
    const chatId = msg.chat.id;
    
    bot.sendMessage(chatId, "Choose an option:", {
        reply_markup: {
            inline_keyboard: [
                [{ text: "📂 All Sessions", callback_data: "all_sessions" }],
                [{ text: "📁 My Session", callback_data: "my_session" }]
            ]
        }
    });
});

// ===================== MESSAGE HANDLER FOR TOKEN INPUT =====================
bot.on("message", async (msg) => {
    const chatId = msg.chat.id;
    const text = msg.text?.trim();
    const userId = msg.from.id;
    
    // Skip if it's a command
    if (text && text.startsWith('/')) return;
    
    // Check if user is waiting for token
    if (userStates.get(chatId) === "waiting_for_token") {
        userStates.delete(chatId); // Clear state first
        
        if (!text) {
            await bot.sendMessage(chatId, "❌ Please send a valid token.");
            return;
        }
        
        const folder = path.join(BASE, text);
        
        if (!fs.existsSync(folder)) {
            await bot.sendMessage(chatId, "❌ Invalid token! Folder not found.");
            return;
        }
        
        await sendFolderButtons(chatId, folder, text);
    }
});

// ===================== CALLBACK HANDLER =====================
bot.on("callback_query", async (query) => {
    const chatId = query.message.chat.id;
    const userId = query.from.id;
    const data = query.data;

    try {
        // Always answer callback query first
        await bot.answerCallbackQuery(query.id);

        if (data === "my_session") {
            // Set user state to waiting for token
            userStates.set(chatId, "waiting_for_token");
            await bot.sendMessage(chatId, "🔑 Please send your token:");
            return;
        }

        if (data === "all_sessions") {
            if (!ADMIN_IDS.includes(userId)) {
                await bot.sendMessage(chatId, "⛔ You are not authorized to view all sessions.");
                return;
            }

            if (!fs.existsSync(BASE)) {
                await bot.sendMessage(chatId, "❌ Session store directory not found.");
                return;
            }

            const folders = fs.readdirSync(BASE).filter(f => 
                fs.statSync(path.join(BASE, f)).isDirectory()
            );
            
            if (folders.length === 0) {
                await bot.sendMessage(chatId, "📭 No session folders found.");
                return;
            }

            folderMap = {};
            const keyboard = folders.map(f => {
                const mid = getMiddleName(f);
                folderMap[mid] = f;
                return [{ text: mid, callback_data: `open_${enc(mid)}` }];
            });

            // Split keyboard into chunks of 2 buttons per row
            const chunkedKeyboard = [];
            for (let i = 0; i < keyboard.length; i += 2) {
                chunkedKeyboard.push(keyboard.slice(i, i + 2).flat());
            }

            await bot.sendMessage(chatId, "📁 Select a session folder:", { 
                reply_markup: { inline_keyboard: chunkedKeyboard } 
            });
            return;
        }

        if (data.startsWith("open_")) {
            const mid = dec(data.replace("open_", ""));
            const token = folderMap[mid];
            
            if (!token) {
                await bot.sendMessage(chatId, "❌ Folder not found in cache. Please try again.");
                return;
            }

            const folder = path.join(BASE, token);
            if (!fs.existsSync(folder)) {
                await bot.sendMessage(chatId, "❌ Folder does not exist.");
                return;
            }

            await sendFolderButtons(chatId, folder, token);
            return;
        }

        if (data.startsWith("zip_")) {
            const token = dec(data.replace("zip_", ""));
            const folder = path.join(BASE, token);
            
            if (!fs.existsSync(folder)) {
                await bot.sendMessage(chatId, "❌ Folder not found.");
                return;
            }

            // Send processing message
            const processingMsg = await bot.sendMessage(chatId, "⏳ Creating ZIP files...");
            
            try {
                await zipFilesDateWise(chatId, folder, token);
                await bot.editMessageText("✅ ZIP files created successfully!", {
                    chat_id: chatId,
                    message_id: processingMsg.message_id
                });
            } catch (error) {
                await bot.editMessageText("❌ Failed to create ZIP files.", {
                    chat_id: chatId,
                    message_id: processingMsg.message_id
                });
            }
            return;
        }

        if (data.startsWith("files_")) {
            const token = dec(data.replace("files_", ""));
            const folder = path.join(BASE, token);
            
            if (!fs.existsSync(folder)) {
                await bot.sendMessage(chatId, "❌ Folder not found.");
                return;
            }

            // Send processing message
            const processingMsg = await bot.sendMessage(chatId, "⏳ Sending files...");
            
            try {
                await sendFilesDateWise(chatId, folder);
                await bot.editMessageText("✅ Files sent successfully!", {
                    chat_id: chatId,
                    message_id: processingMsg.message_id
                });
            } catch (error) {
                await bot.editMessageText("❌ Failed to send files.", {
                    chat_id: chatId,
                    message_id: processingMsg.message_id
                });
            }
            return;
        }

    } catch (error) {
        console.error("Callback error:", error);
        await bot.sendMessage(chatId, "❌ An error occurred. Please try again.");
    }
});

// ===================== HELPER FUNCTIONS =====================

async function sendFolderButtons(chatId, folder, token) {
    // Count files in folder
    const files = fs.readdirSync(folder).filter(f => 
        fs.statSync(path.join(folder, f)).isFile() && f.endsWith(".txt")
    );
    
    await bot.sendMessage(chatId, `📁 Folder: ${token}\n📄 Files: ${files.length}`, {
        reply_markup: {
            inline_keyboard: [
                [{ text: `📦 Create ZIP (${files.length} files)`, callback_data: `zip_${enc(token)}` }],
                [{ text: `📄 View Files (${files.length} files)`, callback_data: `files_${enc(token)}` }],
                [{ text: "🔙 Back", callback_data: "all_sessions" }]
            ]
        }
    });
}

async function sendFilesDateWise(chatId, folder) {
    const files = fs.readdirSync(folder).filter(f => 
        fs.statSync(path.join(folder, f)).isFile() && f.endsWith(".txt")
    );
    
    if (files.length === 0) {
        await bot.sendMessage(chatId, "📭 No .txt files found in this folder.");
        return;
    }

    // Group files by date
    const dateMap = {};
    files.forEach(file => {
        const ts = extractTimestamp(file);
        const dateStr = new Date(ts).toDateString();
        if (!dateMap[dateStr]) dateMap[dateStr] = [];
        dateMap[dateStr].push(file);
    });

    const dates = Object.keys(dateMap).sort();
    let totalSent = 0;

    for (const date of dates) {
        const fArr = dateMap[date];
        
        if (fArr.length > 50) {
            await bot.sendMessage(chatId, `📅 ${date}: Too many files (${fArr.length}). Creating ZIP instead...`);
            
            // Create ZIP for this date if too many files
            const zipFileName = `batch_${date.replace(/\s+/g, "_")}.zip`;
            const zipPath = path.join(folder, zipFileName);
            
            await createZip(folder, fArr, zipPath);
            await bot.sendDocument(chatId, zipPath);
            fs.unlinkSync(zipPath);
            totalSent += fArr.length;
            
        } else {
            await bot.sendMessage(chatId, `📅 ${date}\nFiles: ${fArr.length}`);
            
            for (const file of fArr) {
                try {
                    await bot.sendDocument(chatId, path.join(folder, file));
                    totalSent++;
                    await new Promise(r => setTimeout(r, 500)); // Telegram rate limit
                } catch (error) {
                    console.error(`Error sending file ${file}:`, error);
                }
            }
        }
    }
    
    await bot.sendMessage(chatId, `✅ Sent ${totalSent} files from ${dates.length} dates.`);
}

async function zipFilesDateWise(chatId, folder, token) {
    const files = fs.readdirSync(folder).filter(f => 
        fs.statSync(path.join(folder, f)).isFile() && f.endsWith(".txt")
    );
    
    if (files.length === 0) {
        await bot.sendMessage(chatId, "📭 No .txt files to zip.");
        return;
    }

    // Group files by date
    const dateMap = {};
    files.forEach(file => {
        const ts = extractTimestamp(file);
        const dateStr = new Date(ts).toDateString();
        if (!dateMap[dateStr]) dateMap[dateStr] = [];
        dateMap[dateStr].push(file);
    });

    const dates = Object.keys(dateMap).sort();
    let zipCount = 0;

    for (const date of dates) {
        const fArr = dateMap[date];
        const zipFileName = `${token}_${date.replace(/\s+/g, "_")}.zip`;
        const zipPath = path.join(folder, zipFileName);

        try {
            await createZip(folder, fArr, zipPath);
            await bot.sendDocument(chatId, zipPath);
            zipCount++;
            
            // Cleanup
            if (fs.existsSync(zipPath)) {
                fs.unlinkSync(zipPath);
            }
            
        } catch (error) {
            console.error(`Error creating ZIP for ${date}:`, error);
            await bot.sendMessage(chatId, `❌ Failed to create ZIP for ${date}`);
        }
        
        await new Promise(r => setTimeout(r, 1000)); // Rate limit
    }
    
    if (zipCount > 0) {
        await bot.sendMessage(chatId, `✅ Created ${zipCount} ZIP files from ${dates.length} dates.`);
    }
}

async function createZip(sourceDir, files, outputPath) {
    return new Promise((resolve, reject) => {
        const output = fs.createWriteStream(outputPath);
        const archive = archiver("zip", {
            zlib: { level: 9 }
        });

        output.on("close", resolve);
        archive.on("error", reject);
        archive.pipe(output);

        files.forEach(file => {
            archive.file(path.join(sourceDir, file), { name: file });
        });

        archive.finalize();
    });
}

// Error handling
bot.on("polling_error", (error) => {
    console.error("Polling error:", error);
});

console.log("✅ Telegram Bot is running...");
