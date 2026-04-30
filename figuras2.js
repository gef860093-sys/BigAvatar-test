require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const fsp = require('fs/promises');
const cors = require('cors');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { EventEmitter } = require('events');
const Redis = require('ioredis');
const helmet = require('helmet');
const compression = require('compression');
const hpp = require('hpp');
const Database = require('better-sqlite3');

EventEmitter.defaultMaxListeners = 15000;

// ==========================================
// 🎨 ระบบ Logging
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
let LIMIT_BYTES = 35 * 1024 * 1024; // 35MB
const ENABLE_WHITELIST = true;
const TOKEN_MAX_AGE_MS = 6 * 60 * 60 * 1000;

const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || "";
const API_URL = process.env.API_URL || "https://bigavatar.dpdns.org/api.php";
const API_KEY = process.env.API_KEY || "eb84ce2b1f25c448782da7c15484acf5";
const DASHBOARD_PASS = process.env.DASHBOARD_PASS || "admin123";
const SERVER_ZONE = process.env.SERVER_ZONE || "TH";

const ZONE_INFO = { "TH": { webFlag: "🇹🇭", mcFlag: "[TH]", name: "Thailand", ping: "< 20 ms" } };
const currentZone = ZONE_INFO[SERVER_ZONE] || ZONE_INFO["TH"];

const MOTD_MESSAGE = `§8§m                                        §r\n  §3§l✦ §b§lB§3§lI§b§lG§3§lA§b§lV§3§lA§b§lT§3§lA§b§lR §f§lC§7§lL§f§lO§7§lU§f§lD §b§l✦\n§8§m                                        §r\n§a ✔ §aสถานะ: §fออนไลน์ \n§e ⚑ §eโซนเซิร์ฟเวอร์: §f${currentZone.mcFlag} ${currentZone.name}\n§8§m                                        §r`;

// ==========================================
// 💾 DATABASE & STORAGE SETUP
// ==========================================
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
const tokens = new Map();
const wsMap = new Map();
let hashCache = new LRUCache(3000);
let apiJsonCache = new LRUCache(3000);

let sqlBlacklist = new Set();
let sqlWhitelist = new Set();
let isSyncing = false;
let isMaintenanceMode = false;

const fastAxios = axios.create({ timeout: 15000 });

const formatUuid = (uuid) => {
    if (!uuid) return "";
    const clean = uuid.replace(/-/g, '').toLowerCase();
    return clean.length === 32 ? `${clean.slice(0, 8)}-${clean.slice(8, 12)}-${clean.slice(12, 16)}-${clean.slice(16, 20)}-${clean.slice(20)}` : uuid;
};
const isValidUUID = (uuid) => /^[0-9a-fA-F-]{32,36}$/.test(uuid);

// ==========================================
// 📡 BROADCAST ENGINE
// ==========================================
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

const redisPub = process.env.REDIS_URL ? new Redis(process.env.REDIS_URL) : null;
const redisSub = process.env.REDIS_URL ? new Redis(process.env.REDIS_URL) : null;

if (redisSub) {
    redisSub.subscribe('avatar-broadcast').catch(()=>{});
    redisSub.on('message', (channel, message) => {
        if (channel === 'avatar-broadcast') {
            const data = JSON.parse(message);
            broadcastToLocalWatchers(data.uuid, Buffer.from(data.bufferHex, 'hex'));
        }
    });
}

const broadcastGlobal = (uuid, buffer, excludeWs = null) => {
    broadcastToLocalWatchers(uuid, buffer, excludeWs);
    if (redisPub) redisPub.publish('avatar-broadcast', JSON.stringify({ uuid: uuid, bufferHex: buffer.toString('hex') })).catch(()=>{});
};

// ==========================================
// 🌐 EXPRESS HTTP SERVER
// ==========================================
const app = express();
app.set('trust proxy', 1);

app.use(cors());
app.use(helmet({ contentSecurityPolicy: false }));
app.use(hpp());
app.use(compression({ threshold: 512, filter: (req, res) => req.headers['content-type'] === 'application/octet-stream' ? false : compression.filter(req, res) }));

// 🛠️ FIX ปัญหาที่ 6 (URL บั๊ก / Double Slashes): ตัดปัญหาหน้าจอแดง 100%
app.use((req, res, next) => {
    const urlParts = req.url.split('?');
    urlParts[0] = urlParts[0].replace(/\/{2,}/g, '/');
    req.url = urlParts.join('?');
    res.setTimeout(120000, () => { if (!res.headersSent) res.status(408).end(); }); 
    next(); 
});

const bannedIPs = new Map();
app.use((req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (bannedIPs.has(ip)) {
        if (Date.now() < bannedIPs.get(ip)) return res.status(403).send("§cIP ของคุณถูกแบนชั่วคราว");
        bannedIPs.delete(ip);
    }
    req.clientIp = ip;
    next();
});

const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 300 });
const uploadLimiter = rateLimit({ windowMs: 60 * 1000, max: 20 });

// 🛠️ FIX ปัญหาที่ 1 และ 4 (โมเดลพัง/ค้าง 0%): ใช้ express.raw สำหรับการอัปโหลดไฟล์ (ไม่ใช้ Stream)
app.use('/api/avatar', uploadLimiter, express.raw({ type: '*/*', limit: '35mb' }));
app.use(express.json({ limit: '5mb' })); 
app.use('/api/', apiLimiter);

// 🛠️ FIX ปัญหา Java Mod (Stardust) Watchdog: เพิ่ม Route /ping เพื่อไม่ให้ Thread ในเกมแจ้ง Error
app.get('/ping', (req, res) => res.status(200).send("PONG"));

app.get('/health', (req, res) => res.status(200).json({ status: 'UP', localPlayers: tokens.size, uptime: process.uptime() }));
app.get('/api/motd', (req, res) => res.status(200).send(MOTD_MESSAGE));
app.get('/api/version', (req, res) => res.json({"release":"0.1.5", "prerelease":"0.1.5"}));
app.get('/api/limits', (req, res) => res.json({"rate": { "pingSize": 1048576, "pingRate": 4096, "equip": 0, "download": 999999999999, "upload": 99999999999 }, "limits": { "maxAvatarSize": LIMIT_BYTES, "maxAvatars": 100, "allowedBadges": { "special": Array(15).fill(0), "pride": Array(30).fill(0) } }}));

app.get('/api/auth/id', (req, res) => {
    const uname = req.query.username?.toLowerCase();
    if (!uname) return res.status(400).end();
    if (isMaintenanceMode) return res.status(403).send("§e⚠ เซิร์ฟเวอร์ปิดปรับปรุง");
    if (sqlBlacklist.has(uname)) return res.status(403).send("§c✖ บัญชีถูกระงับ");
    if (ENABLE_WHITELIST && !sqlWhitelist.has(uname)) return res.status(403).send("§c✖ ไม่มีชื่อในระบบ");

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
            lastAccess: Date.now(), createdAt: Date.now(), activeSockets: new Set() 
        });
        
        serverStats.totalLogins++; saveStatsDB();
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
    const buffer = Buffer.alloc(17); buffer.writeUInt8(2, 0); 
    req.userInfo.hexUuidBuffer.copy(buffer, 1); 
    broadcastGlobal(req.userInfo.uuid, buffer); 
    res.send("success");
});

app.put('/api/avatar', authMiddleware, async (req, res) => {
    const userInfo = req.userInfo;
    userInfo.lastAccess = Date.now(); 

    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
        return res.status(400).send({ error: "Empty file upload" });
    }

    if (req.body.length > LIMIT_BYTES) {
        bannedIPs.set(req.clientIp, Date.now() + 15 * 60 * 1000); 
        return res.status(413).end();
    }

    const finalFile = path.join(avatarsDir, `${userInfo.uuid}.moon`);
    try {
        await fsp.writeFile(finalFile, req.body); // เซฟก้อนเดียวจบ ป้องกันไฟล์แตก
        const finalHash = crypto.createHash('sha256').update(req.body).digest('hex');
        
        hashCache.set(userInfo.uuid, finalHash); 
        apiJsonCache.delete(userInfo.uuid); 
        serverStats.totalUploads++; serverStats.totalBytes += req.body.length; saveStatsDB();
        
        const buffer = Buffer.alloc(17); buffer.writeUInt8(2, 0); 
        userInfo.hexUuidBuffer.copy(buffer, 1); 
        broadcastGlobal(userInfo.uuid, buffer); 
        
        res.send("success"); 
    } catch (err) {
        res.status(500).send({ error: "Upload failed" });
    }
});

app.delete('/api/avatar', authMiddleware, async (req, res) => {
    const userInfo = req.userInfo;
    try {
        userInfo.lastAccess = Date.now();
        await fsp.unlink(path.join(avatarsDir, `${userInfo.uuid}.moon`)); 
        hashCache.delete(userInfo.uuid); apiJsonCache.delete(userInfo.uuid); 
        
        const buffer = Buffer.alloc(17); buffer.writeUInt8(2, 0); 
        userInfo.hexUuidBuffer.copy(buffer, 1); 
        broadcastGlobal(userInfo.uuid, buffer); 
        res.send("success");
    } catch (err) { res.status(404).end(); }
});

app.get('/api/:uuid/avatar', async (req, res) => { 
    const uuidStr = req.params.uuid;
    if (!isValidUUID(uuidStr)) return res.status(404).end();
    
    const avatarFile = path.join(avatarsDir, `${formatUuid(uuidStr)}.moon`);
    try {
        await fsp.access(avatarFile); 
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate'); // แก้ปัญหาสกินไม่อัปเดต
        res.setHeader('Content-Type', 'application/octet-stream');
        res.sendFile(avatarFile);
    } catch (e) { res.status(404).end(); }
});

app.get('/api/:uuid', async (req, res) => {
    const uuidStr = req.params.uuid;
    if (!isValidUUID(uuidStr)) return res.status(404).end();
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

// ==========================================
// ⚡ WEBSOCKET ENGINE (ACTION WHEEL & ANIMATION FIX)
// ==========================================
const server = http.createServer(app);
server.keepAliveTimeout = 120000;  

const wss = new WebSocket.Server({ server, perMessageDeflate: false, maxPayload: 2097152 });
const MAX_WS = 5000; 
const RATE_LIMIT_WS_MSGS = 150; 

setInterval(() => { wss.clients.forEach(ws => { ws.msgCount = 0; }); }, 1000);

wss.on('connection', (ws) => {
    if (wss.clients.size > MAX_WS) return ws.terminate();

    ws.isAlive = true; 
    ws.isAuthenticated = false; 
    ws.msgCount = 0; 
    ws.watchedUuids = new Set(); 
    
    const authTimeout = setTimeout(() => {
        if (!ws.isAuthenticated) ws.terminate();
    }, 10000);

    ws.on('pong', () => { ws.isAlive = true; }); 

    ws.on('message', (data) => {
        try {
            ws.msgCount++;
            if (ws.msgCount > RATE_LIMIT_WS_MSGS) return; // ไม่เตะออก แค่เมินข้อความ ป้องกันเกมหลุด

            if (!Buffer.isBuffer(data) || data.length < 1) return; 

            const type = data[0];
            if (type === 0) {
                const tokenStr = data.slice(1).toString('utf-8').trim();
                const userInfo = tokens.get(tokenStr);

                if (userInfo) {
                    clearTimeout(authTimeout); 
                    ws.isAuthenticated = true;
                    ws.userInfo = userInfo; 
                    userInfo.activeSockets.add(ws); 
                    if (ws.readyState === WebSocket.OPEN) ws.send(Buffer.from([0]), { binary: true });
                } else {
                    ws.terminate(); 
                }
            }
            // 🛠️ FIX ปัญหาที่ 2 และ 3: ระบบ Relay ที่สมบูรณ์ที่สุด (Agnostic Protocol)
            // คัดลอก Payload ทั้งหมดจากเกม (ไม่ว่าจะเป็น Action Wheel หรือแอนิเมชัน) แล้วแปะ UUID ส่งกลับไปให้ทุกคน
            else if (type === 1) { 
                if (!ws.isAuthenticated || data.length < 1 || !ws.userInfo) return; 
                const userInfo = ws.userInfo;
                userInfo.lastAccess = Date.now(); 
                
                // รูปแบบ S2C: [0 (Byte)] + [UUID (16 Bytes)] + [Payload (N Bytes ที่รับมาทั้งหมด)]
                const payload = data.slice(1); // ตัด Byte แรกของ C2S ออก (ซึ่งคือเลข 1)
                const newbuffer = Buffer.alloc(17 + payload.length);
                
                newbuffer.writeUInt8(0, 0); // ส่งรหัส 0 (S2C Broadcast) กลับไปให้ Client ตัวอื่น
                userInfo.hexUuidBuffer.copy(newbuffer, 1); // แปะ UUID ของคนกด
                payload.copy(newbuffer, 17); // แปะข้อมูล Action/Animation ตามมาทันที (ไม่ตัด ไม่แต่ง ไม่หั่น)
                
                // กระจายไปหาทุกคนที่มองเห็น UUID นี้
                broadcastGlobal(userInfo.uuid, newbuffer, ws);
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
        if (ws.userInfo) ws.userInfo.activeSockets.delete(ws);
        ws.watchedUuids.forEach(uuid => {
            const watchers = wsMap.get(uuid);
            if (watchers) {
                watchers.delete(ws);
                if (watchers.size === 0) wsMap.delete(uuid);
            }
        });
    });
});

const wsPingInterval = setInterval(() => { 
    wss.clients.forEach((ws) => { 
        if (!ws.isAlive) return ws.terminate();
        ws.isAlive = false; 
        if (ws.readyState === WebSocket.OPEN) ws.ping(); 
    }); 
}, 25000); 

wss.on('close', () => clearInterval(wsPingInterval));

// ==========================================
// 🛡️ TASKS & SYNC
// ==========================================
setInterval(saveStatsDB, 60 * 1000);

const cleanupTask = setInterval(async () => { 
    const now = Date.now();
    for (const [tokenStr, userInfo] of tokens.entries()) {
        if (now - userInfo.createdAt > TOKEN_MAX_AGE_MS || (userInfo.activeSockets.size === 0 && now - userInfo.lastAccess > 3600000)) { 
            userInfo.activeSockets.forEach(ws => { try { ws.terminate(); } catch(e){} }); 
            tokens.delete(tokenStr); 
        }
    }
}, 5 * 60 * 1000); 

const syncTask = setInterval(async () => {
    if (isSyncing) return; 
    isSyncing = true;
    try {
        if (!API_URL || !API_KEY) return; 
        const formData = new URLSearchParams({ key: API_KEY, action: 'get_lists' });
        const res = await fastAxios.post(API_URL, formData.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }});

        if (res.data && res.data.maintenance === true) {
            isMaintenanceMode = true;
        } else {
            isMaintenanceMode = false;
            if (res.data && !res.data.error) {
                sqlBlacklist = new Set((res.data.blacklist || []).map(v => String(v).toLowerCase().trim()));
                if (ENABLE_WHITELIST) sqlWhitelist = new Set((res.data.whitelist || []).map(v => String(v).toLowerCase().trim()));
            }
        }
    } catch (e) {} finally { isSyncing = false; }
}, 15000); 

const shutdown = () => {
    logger.info(`\n${c.y}⚠️ กำลังปิดเซิร์ฟเวอร์อย่างปลอดภัย...${c.rst}`);
    clearInterval(syncTask); clearInterval(cleanupTask); clearInterval(wsPingInterval);
    if (redisPub) redisPub.quit(); if (redisSub) redisSub.quit();
    saveStatsDB();
    if (db) db.close(); 
    wss.close(() => { server.close(() => { logger.info(`${c.g}✅ ปิดเสร็จสมบูรณ์${c.rst}`); process.exit(0); }); });
};
process.on('SIGTERM', shutdown); process.on('SIGINT', shutdown);

server.listen(PORT, '0.0.0.0', () => {
    logger.info(`\n${c.p}==========================================${c.rst}`);
    logger.info(`${c.b}✨ BIGAVATAR CLOUD (CORE V5: STABLE RELAY) ${c.rst}`);
    logger.info(`${c.g}✅ Server Region: ${currentZone.name} ${currentZone.mcFlag}${c.rst}`);
    logger.info(`${c.y}🛡️ Double Slash Fix: ACTIVE${c.rst}`);
    logger.info(`${c.y}🛡️ Agnostic WebSocket Relay (Fix Anim/Wheel): ACTIVE${c.rst}`);
    logger.info(`${c.y}🛡️ Watchdog Support (/ping): ACTIVE${c.rst}`);
    logger.info(`${c.p}==========================================${c.rst}\n`);
});
