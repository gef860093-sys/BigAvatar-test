require('dotenv').config(); 
const express = require('express');
const http = require('http'); 
const https = require('https');
const WebSocket = require('ws');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const fsp = require('fs/promises');
const { pipeline } = require('stream/promises');
const { Transform } = require('stream'); 
const cors = require('cors');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit'); 
const os = require('os'); 
const { EventEmitter } = require('events');
const Redis = require('ioredis');

const helmet = require('helmet');
const compression = require('compression');
const hpp = require('hpp');
const Database = require('better-sqlite3'); 

EventEmitter.defaultMaxListeners = 15000;

// ==========================================
// 🎨 ระบบสีและ Log สำหรับ Console
// ==========================================
const c = { g: '\x1b[32m', b: '\x1b[36m', y: '\x1b[33m', r: '\x1b[31m', p: '\x1b[35m', rst: '\x1b[0m' };
const logTime = () => `[${new Date().toLocaleTimeString('th-TH')}]`;
const startTime = Date.now();

const getLogFilename = () => {
    const d = new Date();
    return `server-${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}.log`;
};
const writeLog = (type, msg) => {
    const cleanMsg = msg.replace(/\x1b\[[0-9;]*m/g, '');
    fs.appendFile(path.join(__dirname, getLogFilename()), `${type} ${logTime()}: ${cleanMsg}\n`, () => {});
    if (type === 'INFO') console.log(msg); else console.error(msg);
};
const logger = { info: (msg) => writeLog('INFO', msg), error: (msg) => writeLog('ERROR', msg) };

process.on('uncaughtException', (err) => { logger.error(`${c.r}[Fatal Protected] ${err.stack}${c.rst}`); });
process.on('unhandledRejection', (reason) => { logger.error(`${c.r}[Promise Protected] ${reason}${c.rst}`); });

// ==========================================
// ⚙️ SERVER CONFIGURATION
// ==========================================
const PORT = process.env.PORT || 80; 

let LIMIT_BYTES = 50 * 1024 * 1024; 

const ENABLE_WHITELIST = true; 
const TOKEN_MAX_AGE_MS = 12 * 60 * 60 * 1000; 
let UPLOAD_COOLDOWN_MS = 3 * 1000; 
let MOTD_TITLE = "FAYDAR";
let MOTD_SUBTITLE = "Welcome FayDarCloud";

const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || ""; 
const API_URL = process.env.API_URL || "https://bigavatar.dpdns.org/api.php"; 
const API_KEY = process.env.API_KEY || "eb84ce2b1f25c448782da7c15484acf5"; 
const DASHBOARD_PASS = process.env.DASHBOARD_PASS || "admin123";
const SERVER_ZONE = process.env.SERVER_ZONE || "TH"; 
const ADMIN_SECRET = process.env.ADMIN_SECRET || "faydar_super_secret_key"; 

const ZONE_INFO = {
    "TH": { webFlag: "🇹🇭", mcFlag: "[TH]", name: "Thailand", ping: 15 },
};

const currentZone = ZONE_INFO[SERVER_ZONE] || ZONE_INFO["TH"];
const formatMB = (bytes) => (bytes / 1024 / 1024).toFixed(0);

const getPingText = (ping) => {
  if (ping < 20) return "§a< 20 ms"; 
  if (ping < 50) return `§e${ping} ms`;
  return `§c${ping} ms`;
};

const generateMotd = () => {
    return `§b╔══════════════════════════════════════╗§r\n` +
           `§b║     §3§l${MOTD_TITLE.padEnd(14)} §f§lCLOUD §7☁      §b║§r\n` +
           `§b╠══════════════════════════════════════╣§r\n` +
           `§b║ §a● §fสถานะ: §aออนไลน์ §7| §d💾 §fไฟล์: §d${formatMB(LIMIT_BYTES)}MB §b║§r\n` +
           `§b║ §e⚑ §fโซน: §e${currentZone.mcFlag} ${currentZone.name} §7(${getPingText(currentZone.ping)}) §b║§r\n` +
           `§b╠══════════════════════════════════════╣§r\n` +
           `§b║ §7🚀 §fSpeed: §aHigh Performance     §b║§r\n` +
           `§b║ §7🔒 §fSecurity: §a100% Protected    §b║§r\n` +
           `§b║ §7📦 §fStorage: §eUnlimited Ready    §b║§r\n` +
           `§b╠══════════════════════════════════════╣§r\n` +
           `§b║ §d✨ §f${MOTD_SUBTITLE.padEnd(20)} §b║§r\n` +
           `§b╚══════════════════════════════════════╝§r`;
};

let MOTD_MESSAGE = generateMotd();

const SYNC_INTERVAL_MS = 3000;    
const WS_PING_INTERVAL_MS = 25000; 

// ==========================================
// 🔗 REDIS & DATABASE SETUP
// ==========================================
const redisPub = process.env.REDIS_URL ? new Redis(process.env.REDIS_URL) : null;
const redisSub = process.env.REDIS_URL ? new Redis(process.env.REDIS_URL) : null;

if (redisSub) {
    redisSub.subscribe('avatar-broadcast', (err) => { if (err) logger.error(`[Redis] Subscribe Error: ${err.message}`); });
    redisSub.on('message', (channel, message) => {
        if (channel === 'avatar-broadcast') {
            const data = JSON.parse(message);
            broadcastToLocalWatchers(data.uuid, Buffer.from(data.bufferHex, 'hex'));
        }
    });
}

const avatarsDir = path.join(__dirname, "avatars");
const backupDir = path.join(__dirname, "avatars_backup");
if (!fs.existsSync(avatarsDir)) fs.mkdirSync(avatarsDir, { recursive: true });
if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });

const db = new Database(path.join(__dirname, 'serverDB.sqlite'));
db.pragma('journal_mode = WAL');
db.prepare(`CREATE TABLE IF NOT EXISTS stats (id INTEGER PRIMARY KEY, totalLogins INTEGER, totalUploads INTEGER, totalBytes INTEGER)`).run();

let row = db.prepare('SELECT * FROM stats WHERE id = 1').get();
if (!row) {
    db.prepare('INSERT INTO stats (id, totalLogins, totalUploads, totalBytes) VALUES (1, 0, 0, 0)').run();
    row = { totalLogins: 0, totalUploads: 0, totalBytes: 0 };
}
let serverStats = { ...row };

const saveStatsDB = () => {
    try {
        db.prepare('UPDATE stats SET totalLogins = ?, totalUploads = ?, totalBytes = ? WHERE id = 1')
          .run(serverStats.totalLogins, serverStats.totalUploads, serverStats.totalBytes);
    } catch (e) { logger.error(`[DB Error] ${e.message}`); }
};

// ==========================================
// 🌐 EXPRESS APP & MIDDLEWARE
// ==========================================
const app = express();
app.set('trust proxy', 1);

const bannedIPs = new Map();
app.use(express.json({ limit: '1mb' })); // 🔧 Limit payload
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

app.use((req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (bannedIPs.has(ip)) {
        if (Date.now() < bannedIPs.get(ip)) return res.status(403).send("§cIP ของคุณถูกแบนชั่วคราวจากการสแปม");
        bannedIPs.delete(ip); 
    }
    req.clientIp = ip;
    next();
});

app.use(cors({
    origin: '*', 
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'token', 'x-admin-key']
}));

app.use(helmet({ contentSecurityPolicy: false })); 
app.use(hpp()); 

app.use(compression({ 
    threshold: 512, filter: (req, res) => req.headers['content-type'] === 'application/octet-stream' ? false : compression.filter(req, res)
}));

app.use((req, res, next) => {
    // 🔧 ป้องกันบั๊กทำลาย URL Query string
    req.url = req.url.replace(/(?<!:)\/{2,}/g, '/');
    res.setTimeout(120000, () => { if (!res.headersSent) res.status(408).end(); }); 
    next(); 
});

const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 300, message: { error: "Rate Limit Exceeded" } });
const uploadLimiter = rateLimit({ windowMs: 60 * 1000, max: 40, message: { error: "Uploads Limited" } }); 

app.use('/api/', (req, res, next) => { 
    if (req.path === '/avatar' && (req.method === 'PUT' || req.method === 'POST')) return uploadLimiter(req, res, next); 
    next(); 
}, apiLimiter);

// ==========================================
// 🧠 CACHE & STATE MANAGEMENT
// ==========================================
class LRUCache {
    constructor(limit) { this.map = new Map(); this.limit = limit; }
    get(key) {
        if (!this.map.has(key)) return undefined;
        const val = this.map.get(key);
        this.map.delete(key); this.map.set(key, val);
        return val;
    }
    set(key, val) {
        if (this.map.has(key)) this.map.delete(key);
        else if (this.map.size >= this.limit) this.map.delete(this.map.keys().next().value);
        this.map.set(key, val);
    }
    delete(key) { return this.map.delete(key); }
    has(key) { return this.map.has(key); }
}

const server_ids = new LRUCache(1000);
const tokens = new Map(); // 🔧 ยุบรวม State มาไว้ที่นี่ที่เดียว
const wsMap = new Map(); 
let hashCache = new LRUCache(3000); 
let apiJsonCache = new LRUCache(3000); 

let sqlBlacklist = new Set();
let sqlWhitelist = new Set();
let isSyncing = false; 
let isMaintenanceMode = false;
let lastMaintenanceState = false;

const fastAxios = axios.create({ timeout: 5000, httpAgent: new http.Agent({ keepAlive: true, maxSockets: 1000 }), httpsAgent: new https.Agent({ keepAlive: true, maxSockets: 1000 }) });
const sendToDiscord = (message) => { if (DISCORD_WEBHOOK_URL) fastAxios.post(DISCORD_WEBHOOK_URL, { content: message }).catch(() => {}); };
const isValidUUID = (uuid) => /^[0-9a-fA-F-]{32,36}$/.test(uuid);
const formatUuid = (uuid) => {
    if (!uuid) return "";
    const clean = uuid.replace(/-/g, '').toLowerCase(); 
    return clean.length === 32 ? `${clean.slice(0, 8)}-${clean.slice(8, 12)}-${clean.slice(12, 16)}-${clean.slice(16, 20)}-${clean.slice(20)}` : uuid;
};

const broadcastToLocalWatchers = (uuid, buffer, excludeWs = null) => {
    const watchers = wsMap.get(uuid);
    if (!watchers) return;
    watchers.forEach(tws => {
        if (tws === excludeWs) return; 
        try {
            if (tws.readyState === WebSocket.OPEN && tws.bufferedAmount < 1048576) {
                tws.send(buffer, { binary: true });
            } else if (tws.readyState !== WebSocket.OPEN) {
                watchers.delete(tws); 
            }
        } catch (e) { watchers.delete(tws); }
    });
};

const broadcastGlobal = (uuid, buffer, excludeWs = null) => {
    broadcastToLocalWatchers(uuid, buffer, excludeWs);
    if (redisPub) redisPub.publish('avatar-broadcast', JSON.stringify({ uuid: uuid, bufferHex: buffer.toString('hex') })).catch(()=>{});
};

// ==========================================
// 🗑️ GARBAGE COLLECTION & BACKUP
// ==========================================
// 🔧 Save DB บ่อยขึ้น
setInterval(saveStatsDB, 60 * 1000);

const gcInterval = setInterval(async () => { 
    const now = Date.now();
    saveStatsDB(); 
    
    // 🔧 ล้างแบนเนอร์ IP เก่า
    for (const [ip, unbanTime] of bannedIPs.entries()) {
        if (now > unbanTime) bannedIPs.delete(ip);
    }

    for (const [tokenStr, userInfo] of tokens.entries()) {
        const isExpired = now - userInfo.createdAt > TOKEN_MAX_AGE_MS;
        const isInactive = userInfo.activeSockets.size === 0 && now - userInfo.lastAccess > 60 * 60 * 1000; 
        
        if (isExpired || isInactive) { 
            userInfo.activeSockets.forEach(ws => { try { ws.terminate(); } catch(e){} }); 
            tokens.delete(tokenStr); 
        }
    }

    try {
        const files = await fsp.readdir(avatarsDir);
        for (const file of files) {
            if (file.endsWith('.tmp')) {
                const stats = await fsp.stat(path.join(avatarsDir, file)).catch(()=>null);
                if (stats && (now - stats.mtimeMs > 5 * 60 * 1000)) await fsp.unlink(path.join(avatarsDir, file)).catch(()=>{});
            }
        }
    } catch (e) {}
}, 5 * 60 * 1000); 

setInterval(async () => {
    try {
        const now = Date.now();
        const files = await fsp.readdir(avatarsDir);
        for (const file of files) {
            if (file.endsWith('.moon')) await fsp.copyFile(path.join(avatarsDir, file), path.join(backupDir, file)).catch(()=>{});
        }
        
        const backups = await fsp.readdir(backupDir);
        for (const file of backups) {
            const filePath = path.join(backupDir, file);
            const stats = await fsp.stat(filePath).catch(()=>null);
            if (stats && (now - stats.mtimeMs > 24 * 60 * 60 * 1000)) await fsp.unlink(filePath).catch(()=>{});
        }
    } catch (e) {}
}, 60 * 60 * 1000);

// ==========================================
// 🔄 DATABASE SYNC (API POLLING)
// ==========================================
const runSync = async () => {
    if (isSyncing) return; 
    isSyncing = true;
    try {
        if (!API_URL || !API_KEY) return; 
        const formData = new URLSearchParams({ key: API_KEY, action: 'get_lists' });
        const res = await fastAxios.post(API_URL, formData.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }});

        if (res.data && res.data.maintenance === true) {
            isMaintenanceMode = true;
        } else if (res.data && res.data.maintenance === false) {
            isMaintenanceMode = false;
            
            // 🔧 บังคับเป็นพิมพ์เล็กทั้งหมด ป้องกันบั๊กเช็คชื่อไม่ตรง
            if (Array.isArray(res.data.blacklist)) sqlBlacklist = new Set(res.data.blacklist.map(v => String(v).toLowerCase().trim()));
            if (ENABLE_WHITELIST && Array.isArray(res.data.whitelist)) sqlWhitelist = new Set(res.data.whitelist.map(v => String(v).toLowerCase().trim()));
            
            if (res.data.settings) {
                const newLimitMB = parseInt(res.data.settings.max_upload_mb);
                if (!isNaN(newLimitMB) && newLimitMB > 0) LIMIT_BYTES = newLimitMB * 1024 * 1024;
                
                const newCooldownSec = parseInt(res.data.settings.cooldown_sec);
                if (!isNaN(newCooldownSec) && newCooldownSec > 0) UPLOAD_COOLDOWN_MS = newCooldownSec * 1000;

                MOTD_TITLE = res.data.settings.motd_title || "FAYDAR";
                MOTD_SUBTITLE = res.data.settings.motd_subtitle || "Welcome FayDarCloud";
                MOTD_MESSAGE = generateMotd(); 
            }
        }

        if (isMaintenanceMode !== lastMaintenanceState) {
            lastMaintenanceState = isMaintenanceMode;
            if (isMaintenanceMode) sendToDiscord(`⚠️ **[ประกาศ]** เซิร์ฟเวอร์เข้าสู่ **โหมดปิดปรับปรุง (Maintenance)** 🛠️`);
            else sendToDiscord(`✅ **[ประกาศ]** เซิร์ฟเวอร์ **เปิดให้บริการปกติ** แล้ว! 🌍 โซน: ${currentZone.name}`);
        }

        const onlineData = [];
        for (const [tokenStr, userInfo] of tokens.entries()) {
            const uname = userInfo.usernameLower; 
            if (isMaintenanceMode || sqlBlacklist.has(uname) || (ENABLE_WHITELIST && !sqlWhitelist.has(uname))) {
                userInfo.activeSockets.forEach(ws => { try { ws.terminate(); } catch(e){} });
                tokens.delete(tokenStr);
                continue;
            }
            if (userInfo.activeSockets && userInfo.activeSockets.size > 0) {
                onlineData.push({ name: userInfo.username, activity: userInfo.activity, last_size: userInfo.lastSize });
            }
        }
        
        if (!isMaintenanceMode) {
            const hbData = new URLSearchParams({ key: API_KEY, action: 'heartbeat', data: JSON.stringify(onlineData) });
            fastAxios.post(API_URL, hbData.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }}).catch(()=>{});
        }
    } catch (e) {} finally { isSyncing = false; }
};

setTimeout(runSync, 1000); 
const syncInterval = setInterval(runSync, SYNC_INTERVAL_MS); 

// ==========================================
// 🚀 REST API ENDPOINTS
// ==========================================
app.post('/api/admin/kick-avatar', (req, res) => {
    if (req.headers['x-admin-key'] !== ADMIN_SECRET) return res.status(403).json({ success: false, error: "Unauthorized - Invalid Secret Key" });
    
    const targetUsername = req.body.username?.toLowerCase();
    if (!targetUsername) return res.status(400).json({ success: false, error: "Missing username" });

    let kicked = false;
    for (const [tokenStr, userInfo] of tokens.entries()) {
        if (userInfo.usernameLower === targetUsername) {
            userInfo.activeSockets.forEach(ws => { 
                try { ws.close(1000, "Kicked by Admin"); } catch(e) {} 
            });
            tokens.delete(tokenStr);
            kicked = true;
            
            fsp.unlink(path.join(avatarsDir, `${userInfo.uuid}.moon`)).catch(() => {});
            sendToDiscord(`🚨 **[Admin Action]** บังคับลบโมเดลและเตะ \`${targetUsername}\` ออกจากระบบ`);
        }
    }
    res.json({ success: kicked, message: kicked ? "Kicked and removed avatar" : "User not found online" });
});

app.get('/health', (req, res) => res.status(200).json({ status: 'UP', localPlayers: tokens.size, memory: process.memoryUsage().rss / 1024 / 1024, uptime: process.uptime() }));

app.get('/api/server-stats', (req, res) => {
    if (req.query.pass !== DASHBOARD_PASS) return res.status(403).json({ error: "Unauthorized" });
    const uptimeSecs = Math.floor((Date.now() - startTime) / 1000);
    res.json({
        totalLogins: serverStats.totalLogins, totalUploads: serverStats.totalUploads,
        totalBytesMB: (serverStats.totalBytes / 1024 / 1024).toFixed(2), ramUsageMB: (process.memoryUsage().rss / 1024 / 1024).toFixed(2),
        uptimeStr: `${Math.floor(uptimeSecs/3600)}h ${Math.floor((uptimeSecs%3600)/60)}m ${uptimeSecs%60}s`, zone: currentZone
    });
});

app.get('/api/motd', (req, res) => { res.type('text/plain').status(200).send(MOTD_MESSAGE); });
app.get('/api/version', (req, res) => res.json({"release":"0.1.5", "prerelease":"0.1.5"}));
app.get('/api/limits', (req, res) => res.json({"rate": { "pingSize": 1048576, "pingRate": 4096, "equip": 0, "download": 999999999999, "upload": 99999999999 }, "limits": { "maxAvatarSize": LIMIT_BYTES, "maxAvatars": 100, "allowedBadges": { "special": Array(15).fill(0), "pride": Array(30).fill(0) } }}));

app.get('/api/auth/id', (req, res) => {
    const uname = req.query.username?.toLowerCase();
    if (!uname) return res.status(400).end();

    if (isMaintenanceMode) return res.status(403).send("§e⚠ เซิร์ฟเวอร์อยู่ในโหมดปิดปรับปรุงชั่วคราว");
    if (sqlBlacklist.has(uname)) return res.status(403).send("§c✖ บัญชีของคุณถูกระงับ (Banned)");
    if (ENABLE_WHITELIST && !sqlWhitelist.has(uname)) return res.status(403).send("§c✖ ไม่มีชื่อในระบบ (Not Whitelisted)");

    const serverID = crypto.randomBytes(16).toString('hex');
    server_ids.set(serverID, { username: req.query.username, time: Date.now() });
    res.send(serverID);
});

app.get('/api/auth/verify', async (req, res) => {
    try {
        const sid = req.query.id;
        const sessionData = server_ids.get(sid);
        if (!sessionData) return res.status(404).json({ error: 'Auth failed' });
        
        const response = await fastAxios.get("https://sessionserver.mojang.com/session/minecraft/hasJoined", { params: { username: sessionData.username, serverId: sid } });
        server_ids.delete(sid); 
        
        const token = crypto.randomBytes(16).toString('hex');
        const hexUuid = response.data.id;
        const premiumUuid = formatUuid(hexUuid);
        const hexUuidBuffer = Buffer.from(hexUuid, 'hex'); 

        tokens.set(token, { 
            uuid: premiumUuid, hexUuid: hexUuid, hexUuidBuffer: hexUuidBuffer, 
            username: response.data.name, usernameLower: response.data.name.toLowerCase(),
            lastSize: 0, lastAccess: Date.now(), createdAt: Date.now(),
            activeSockets: new Set(),
            activity: "Idle", cooldownUntil: 0, spamStrikes: 0 // 🔧 รวม State
        });
        
        serverStats.totalLogins++; saveStatsDB();
        logger.info(`${c.b}⚡ [LOGIN] ${c.g}${response.data.name} ${c.p}[${premiumUuid}]${c.rst}`);
        res.send(token);
    } catch (error) { res.status(500).json({ error: 'Auth Error' }); }
});

const authMiddleware = (req, res, next) => {
    const userInfo = tokens.get(req.headers['token']);
    if (!userInfo) return res.status(401).end();
    req.userInfo = userInfo;
    next();
};

app.post('/api/equip', authMiddleware, (req, res) => {
    req.userInfo.lastAccess = Date.now();
    req.userInfo.activity = "👕 สวมใส่โมเดล...";
    
    const buffer = Buffer.alloc(17); buffer.writeUInt8(2, 0); 
    req.userInfo.hexUuidBuffer.copy(buffer, 1); 
    
    broadcastGlobal(req.userInfo.uuid, buffer); 
    res.status(200).json({ success: true });
});

const handleAvatarUpload = async (req, res) => {
    const userInfo = req.userInfo;
    const now = Date.now();
    
    if (userInfo.cooldownUntil && now < userInfo.cooldownUntil) return res.status(429).json({ error: "Wait cooldown" });

    userInfo.lastAccess = now; 
    userInfo.activity = "📤 กำลังอัปโหลด...";

    const tempFile = path.join(avatarsDir, `${userInfo.uuid}_${now}.tmp`);
    const finalFile = path.join(avatarsDir, `${userInfo.uuid}.moon`);
    const writeStream = fs.createWriteStream(tempFile);
    const hash = crypto.createHash('sha256');
    let uploadedBytes = 0;

    const processStream = new Transform({
        transform(chunk, encoding, callback) {
            uploadedBytes += chunk.length;
            if (uploadedBytes > LIMIT_BYTES) return callback(new Error('LIMIT_EXCEEDED'));
            hash.update(chunk);
            callback(null, chunk);
        }
    });

    try {
        await pipeline(req, processStream, writeStream);

        if (uploadedBytes === 0) {
            await fsp.unlink(tempFile).catch(()=>{});
            return res.status(400).json({ error: "Empty file" });
        }

        const finalHash = hash.digest('hex');
        await fsp.rename(tempFile, finalFile); 
        
        userInfo.lastSize = uploadedBytes;
        userInfo.cooldownUntil = now + UPLOAD_COOLDOWN_MS;
        userInfo.spamStrikes = 0;
        userInfo.activity = "✅ พร้อมใช้งาน";

        hashCache.set(userInfo.uuid, finalHash); 
        apiJsonCache.delete(userInfo.uuid); 

        serverStats.totalUploads++; serverStats.totalBytes += uploadedBytes; saveStatsDB();
        
        const buffer = Buffer.alloc(17); buffer.writeUInt8(2, 0); 
        userInfo.hexUuidBuffer.copy(buffer, 1); 
        broadcastGlobal(userInfo.uuid, buffer); 
        
        res.status(200).json({ success: true, hash: finalHash }); 
    } catch (err) {
        await fsp.unlink(tempFile).catch(()=>{}); // 🔧 ลบไฟล์ทันทีเมื่อพัง
        
        if (err.message === 'LIMIT_EXCEEDED') {
            userInfo.spamStrikes += 1;
            if (userInfo.spamStrikes >= 3) {
                bannedIPs.set(req.clientIp, Date.now() + 15 * 60 * 1000); 
                sendToDiscord(`🚨 **[Auto-Ban]** ผู้เล่น \`${userInfo.username}\` ถูกแบน IP 15 นาที ฐานสแปมไฟล์ใหญ่`);
            }
            return res.status(413).json({ error: "Payload Too Large" });
        }
        logger.error(`${c.r}[Upload Error] ${err.message}${c.rst}`);
        if (!res.headersSent) res.status(500).json({ error: "Upload failed" });
    }
};

app.put('/api/avatar', authMiddleware, handleAvatarUpload);
app.post('/api/avatar', authMiddleware, handleAvatarUpload);

app.delete('/api/avatar', authMiddleware, async (req, res) => {
    const userInfo = req.userInfo;
    try {
        userInfo.lastAccess = Date.now();
        userInfo.activity = "🗑️ ลบโมเดล";
        await fsp.unlink(path.join(avatarsDir, `${userInfo.uuid}.moon`)); 
        
        hashCache.delete(userInfo.uuid); apiJsonCache.delete(userInfo.uuid); 
        
        const buffer = Buffer.alloc(17); buffer.writeUInt8(2, 0); 
        userInfo.hexUuidBuffer.copy(buffer, 1); 
        broadcastGlobal(userInfo.uuid, buffer); 
        
        res.status(200).json({ success: true }); 
    } catch (err) { res.status(404).end(); }
});

app.get('/api/:uuid/avatar', async (req, res) => { 
    const uuidStr = req.params.uuid;
    if (["motd", "version", "auth", "limits", "stats-secret"].includes(uuidStr) || !isValidUUID(uuidStr)) return res.status(404).end();
    
    const avatarFile = path.join(avatarsDir, `${formatUuid(uuidStr)}.moon`);
    try {
        await fsp.access(avatarFile); 
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        res.setHeader('Content-Type', 'application/octet-stream');
        res.sendFile(avatarFile);
    } catch (e) { res.status(404).end(); }
});

app.get('/api/:uuid', async (req, res) => {
    const uuidStr = req.params.uuid;
    if (["motd", "version", "auth", "limits", "stats-secret"].includes(uuidStr) || !isValidUUID(uuidStr)) return res.status(404).end();
    const uuid = formatUuid(uuidStr);

    if (apiJsonCache.has(uuid)) { return res.json(apiJsonCache.get(uuid)); }

    const data = { uuid: uuid, rank: "normal", equipped: [], lastUsed: new Date().toISOString(), equippedBadges: { special: Array(15).fill(0), pride: Array(30).fill(0) }, version: "0.1.5", banned: false };
    let fileHash = hashCache.get(uuid);
    
    if (!fileHash) {
        try {
            const fileBuffer = await fsp.readFile(path.join(avatarsDir, `${uuid}.moon`));
            fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
            hashCache.set(uuid, fileHash);
        } catch (e) {}
    }
    if (fileHash) data.equipped.push({ id: 'avatar', owner: uuid, hash: fileHash });
    
    apiJsonCache.set(uuid, data);
    res.json(data);
});

app.get('/', (req, res) => { res.type('text/plain').status(200).send(MOTD_MESSAGE); });

app.use((err, req, res, next) => {
    logger.error(`${c.r}[API Error] ${err.stack}${c.rst}`);
    res.status(500).json({ error: 'Internal Server Error' });
});

// ==========================================
// ⚡ WEBSOCKET ENGINE (V3: ANTI-PROXY DROP)
// ==========================================
const server = http.createServer(app);
server.keepAliveTimeout = 120000;  
server.headersTimeout = 125000;    

const wss = new WebSocket.Server({ server, perMessageDeflate: false, maxPayload: 2 * 1024 * 1024 });

const FREE_RAM_MB = Math.floor(os.freemem() / 1024 / 1024);
const MAX_WS = Math.max(500, Math.min(5000, Math.floor(FREE_RAM_MB / 1.5))); 

const RATE_LIMIT_WS_MSGS = 300; 
const KICK_LIMIT_WS_MSGS = 1000; 

setInterval(() => { wss.clients.forEach(ws => { ws.msgCount = 0; }); }, 1000);

wss.on('connection', (ws) => {
    if (wss.clients.size > MAX_WS) return ws.terminate();

    ws.isAlive = true; 
    ws.isAuthenticated = false; 
    ws.missedPings = 0; 
    ws.msgCount = 0; 
    ws.watchedUuids = new Set(); 
    
    const authTimeout = setTimeout(() => {
        if (!ws.isAuthenticated) ws.terminate();
    }, 30000);

    ws.on('pong', () => { ws.isAlive = true; ws.missedPings = 0; }); 

    ws.on('message', (data) => {
        try {
            // 🔧 ตีตราว่ายังหายใจอยู่เสมอเมื่อมีการรับ-ส่งข้อมูล ป้องกันเซิร์ฟหลุด
            ws.isAlive = true;
            ws.missedPings = 0;

            ws.msgCount++;
            
            if (ws.msgCount > KICK_LIMIT_WS_MSGS) return ws.terminate(); 
            if (ws.msgCount > RATE_LIMIT_WS_MSGS) return; 

            if (!Buffer.isBuffer(data) || data.length < 1 || data.length > 1048576) return; 

            const type = data[0];
            if (type === 0) {
                if (ws.isAuthenticated) return;
                const tokenStr = data.slice(1).toString('utf-8').trim();
                if (tokenStr.length > 100) return ws.terminate(); 

                const userInfo = tokens.get(tokenStr);

                if (userInfo) {
                    clearTimeout(authTimeout); 
                    ws.isAuthenticated = true;
                    ws.userInfo = userInfo; 
                    
                    userInfo.activeSockets.forEach(oldWs => { if (oldWs !== ws) { try { oldWs.terminate(); } catch (e) {} } });
                    userInfo.activeSockets.clear();
                    userInfo.activeSockets.add(ws); 
                    
                    if (ws.readyState === WebSocket.OPEN) {
                        try { ws.send(Buffer.from([0]), { binary: true }); } catch (e) {}
                    }
                } else {
                    ws.terminate(); 
                }
            }
            else if (type === 1) { 
                if (!ws.isAuthenticated || data.length < 10 || !ws.userInfo) return; 
                const userInfo = ws.userInfo;
                userInfo.lastAccess = Date.now(); 
                
                const newbuffer = Buffer.alloc(22 + (data.length - 6)); // 🔧 ใช้ Buffer.alloc 
                newbuffer.writeUInt8(0, 0); 
                userInfo.hexUuidBuffer.copy(newbuffer, 1); 
                try {
                    newbuffer.writeInt32BE(data.readInt32BE(1), 17); 
                    const isGlobal = data.readUInt8(5) !== 0 ? 1 : 0;
                    newbuffer.writeUInt8(isGlobal, 21); 
                    data.slice(6).copy(newbuffer, 22);
                    
                    broadcastGlobal(userInfo.uuid, newbuffer, isGlobal === 1 ? null : ws);
                } catch (bufferErr) {}
            }
            else if (type === 2 || type === 3) {
                if (!ws.isAuthenticated || data.length < 17) return; 
                const uuidHex = data.slice(1, 17).toString('hex');
                const uuid = formatUuid(uuidHex);
                
                if (type === 2) { 
                    ws.watchedUuids.add(uuid); 
                    if (!wsMap.has(uuid)) wsMap.set(uuid, new Set()); 
                    wsMap.get(uuid).add(ws); 
                } else { 
                    ws.watchedUuids.delete(uuid);
                    if (wsMap.has(uuid)) wsMap.get(uuid).delete(ws); 
                }
            }
        } catch (e) {} 
    });
    
    ws.on('error', () => {}); 
    
    ws.on('close', () => {
        clearTimeout(authTimeout);

        if (ws.userInfo) {
            ws.userInfo.activeSockets.delete(ws);
        }

        ws.watchedUuids.forEach(uuid => {
            const watchers = wsMap.get(uuid);
            if (watchers) {
                watchers.delete(ws);
                if (watchers.size === 0) wsMap.delete(uuid);
            }
        });
    });
});

// 🔧 แก้บั๊ก Proxy Drop ด้วย Fake Payload
const wsPingInterval = setInterval(() => { 
    const proxyKeepAlivePayload = Buffer.from([255]); 

    wss.clients.forEach((ws) => { 
        if (!ws.isAlive) {
            ws.missedPings++;
            if (ws.missedPings >= 5) return ws.terminate();
        } else { ws.missedPings = 0; }
        
        ws.isAlive = false; 
        if (ws.readyState === WebSocket.OPEN) { 
            try { 
                ws.ping(); 
                if (ws.isAuthenticated) {
                    ws.send(proxyKeepAlivePayload, { binary: true }); // ส่งข้อมูลหลอกกระตุ้นสาย
                }
            } catch(e){} 
        } 
    }); 
}, WS_PING_INTERVAL_MS); 

wss.on('close', () => clearInterval(wsPingInterval));

// ==========================================
// 🛡️ SHUTDOWN SAFETY
// ==========================================
const shutdown = () => {
    logger.info(`\n${c.y}⚠️ กำลังเซฟข้อมูลและปิดเซิร์ฟเวอร์อย่างปลอดภัย...${c.rst}`);
    clearInterval(syncInterval); clearInterval(gcInterval); clearInterval(wsPingInterval);
    if (redisPub) redisPub.quit();
    if (redisSub) redisSub.quit();
    saveStatsDB();
    if (db) db.close(); 
    
    wss.close(() => { server.close(() => { logger.info(`${c.g}✅ ปิดเซิร์ฟเวอร์เสร็จสมบูรณ์${c.rst}`); process.exit(0); }); });
};
process.on('SIGTERM', shutdown); process.on('SIGINT', shutdown);

server.listen(PORT, '0.0.0.0', () => {
    logger.info(`\n${c.p}==========================================${c.rst}`);
    logger.info(`${c.b}✨ FAYDAR CLOUD (V3 ULTIMATE EDITION) ${c.rst}`);
    logger.info(`${c.g}✅ DotEnv Loaded Securely${c.rst}`);
    logger.info(`${c.g}🌍 Server Region: ${currentZone.name} ${currentZone.mcFlag}${c.rst}`);
    logger.info(`${c.g}✅ API Synced: ${API_URL} (3s Interval)${c.rst}`);
    logger.info(`${redisPub ? c.g + '🔗 Redis Connected (Cluster Ready)' : c.y + '⚠️ No Redis (Running in Single Node Mode)'}${c.rst}`);
    logger.info(`${c.y}🌊 Zero-RAM Stream Upload Engine: ACTIVE${c.rst}`);
    logger.info(`${c.y}🛡️ Proxy Anti-Drop (Keep-Alive): ACTIVE${c.rst}`);
    logger.info(`${c.y}💾 SQLite WAL Database System: ACTIVE${c.rst}`);
    logger.info(`${c.p}==========================================${c.rst}\n`);
    
    sendToDiscord(`🚀 **[SYSTEM START]** ระบบ FayDar Cloud V3 พร้อมใช้งานแล้ว! `);
});
