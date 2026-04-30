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

EventEmitter.defaultMaxListeners = 15000;

// ==========================================
// ⚙️ SERVER CONFIG (STABLE BASE)
// ==========================================
const PORT = process.env.PORT || 80;
const LIMIT_BYTES = 35 * 1024 * 1024; // 35MB
const ENABLE_WHITELIST = true;
const TOKEN_MAX_AGE_MS = 6 * 60 * 60 * 1000;

const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || "";
const API_URL = process.env.API_URL || "https://bigavatar.dpdns.org/api.php";
const API_KEY = process.env.API_KEY || "b9a23abea9240f3f2fc325a3e623f8f0";
const DASHBOARD_PASS = process.env.DASHBOARD_PASS || "admin123";
const SERVER_ZONE = process.env.SERVER_ZONE || "TH";

const ZONE_INFO = {
    "TH": { webFlag: "🇹🇭", mcFlag: "[TH]", name: "Thailand", ping: "< 20 ms" }
};
const currentZone = ZONE_INFO[SERVER_ZONE] || ZONE_INFO["TH"];

const MOTD_MESSAGE = `§8§m                                        §r\n  §3§l✦ §b§lB§3§lI§b§lG§3§lA§b§lV§3§lA§b§lT§3§lA§b§lR §f§lC§7§lL§f§lO§7§lU§f§lD §b§l✦\n§8§m                                        §r\n§a ✔ §aสถานะ: §fออนไลน์ \n§e ⚑ §eโซนเซิร์ฟเวอร์: §f${currentZone.mcFlag} ${currentZone.name}\n§8§m                                        §r`;

// ==========================================
// 💾 DATABASE & STORAGE
// ==========================================
const avatarsDir = path.join(__dirname, "avatars");
if (!fs.existsSync(avatarsDir)) fs.mkdirSync(avatarsDir, { recursive: true });

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

const fastAxios = axios.create({ timeout: 15000 });

const formatUuid = (uuid) => {
    if (!uuid) return "";
    const clean = uuid.replace(/-/g, '').toLowerCase();
    return clean.length === 32 ? `${clean.slice(0, 8)}-${clean.slice(8, 12)}-${clean.slice(12, 16)}-${clean.slice(16, 20)}-${clean.slice(20)}` : uuid;
};

// ==========================================
// 📡 BROADCAST ENGINE (FIXED)
// ==========================================
const broadcastToLocalWatchers = (uuid, buffer, excludeWs = null) => {
    const watchers = wsMap.get(uuid);
    if (!watchers) return;
    watchers.forEach(tws => {
        if (tws === excludeWs) return;
        try {
            if (tws.readyState === WebSocket.OPEN) {
                tws.send(buffer, { binary: true });
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
// 🌐 EXPRESS HTTP SERVER (FIXED UPLOAD)
// ==========================================
const app = express();
app.set('trust proxy', 1);

app.use(cors());
app.use(helmet({ contentSecurityPolicy: false }));
app.use(hpp());

const uploadLimiter = rateLimit({ windowMs: 60 * 1000, max: 30 }); // เพิ่มโควต้าอัปโหลด

// ใช้ express.raw แทน Stream แบบเก่า เพื่อแก้ปัญหาไฟล์ค้าง 0%/100% หรือไฟล์พัง
app.use('/api/avatar', uploadLimiter, express.raw({ type: '*/*', limit: '35mb' }));
app.use(express.json({ limit: '1mb' })); 

app.get('/api/motd', (req, res) => res.status(200).send(MOTD_MESSAGE));
app.get('/api/version', (req, res) => res.json({"release":"0.1.5", "prerelease":"0.1.5"}));
app.get('/api/limits', (req, res) => res.json({"rate": { "pingSize": 1048576, "pingRate": 4096, "equip": 0, "download": 999999999999, "upload": 99999999999 }, "limits": { "maxAvatarSize": LIMIT_BYTES, "maxAvatars": 100, "allowedBadges": { "special": Array(15).fill(0), "pride": Array(30).fill(0) } }}));

app.get('/api/auth/id', (req, res) => {
    const uname = req.query.username?.toLowerCase();
    if (!uname) return res.status(400).end();
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

// 🛠️ FIX ปัญหาที่ 1 และ 4 (อัปโหลดพัง/ไฟล์เสีย): เปลี่ยนมารับข้อมูลดิบ (Raw) เซฟลงทีเดียว
app.put('/api/avatar', authMiddleware, async (req, res) => {
    const userInfo = req.userInfo;
    userInfo.lastAccess = Date.now(); 

    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
        return res.status(400).send({ error: "Empty file upload" });
    }

    if (req.body.length > LIMIT_BYTES) {
        return res.status(413).end();
    }

    const finalFile = path.join(avatarsDir, `${userInfo.uuid}.moon`);
    try {
        await fsp.writeFile(finalFile, req.body);
        const finalHash = crypto.createHash('sha256').update(req.body).digest('hex');
        
        hashCache.set(userInfo.uuid, finalHash); 
        apiJsonCache.delete(userInfo.uuid); 
        
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
        // บังคับให้โหลดใหม่เพื่อไม่ให้สกินเก่าค้าง
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
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
// ⚡ WEBSOCKET ENGINE (FIXED ANIMATION/WHEEL)
// ==========================================
const server = http.createServer(app);
server.keepAliveTimeout = 120000;  

const wss = new WebSocket.Server({ server, perMessageDeflate: false, maxPayload: 1048576 });
const MAX_WS = 5000; 

// 🛠️ FIX ปัญหาที่ 5 (Reconnect บ่อย): ขยาย Rate Limit ให้ครอบคลุมการกด Action Wheel รัวๆ
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
            if (ws.msgCount > RATE_LIMIT_WS_MSGS) return; // แค่เมินข้อความ ไม่เตะออก (แก้ Ping สูง/ค้าง)

            if (!Buffer.isBuffer(data) || data.length < 1 || data.length > 1048576) return; 

            const type = data[0];
            if (type === 0) {
                const tokenStr = data.slice(1).toString('utf-8');
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
            // 🛠️ FIX ปัญหาที่ 2 และ 3 (Animation / Action Wheel): ประกอบ Packet กลับให้ถูกต้อง 100%
            else if (type === 1) { 
                if (!ws.isAuthenticated || data.length < 6 || !ws.userInfo) return; 
                const userInfo = ws.userInfo;
                userInfo.lastAccess = Date.now(); 
                
                // รูปแบบที่ถูกต้อง: [ID(1)] + [UUID(16)] + [Int32(4)] + [Boolean(1)] + [Payload(N)]
                const payloadSize = data.length - 6;
                const newbuffer = Buffer.alloc(22 + payloadSize);
                newbuffer.writeUInt8(0, 0); // Event Type สำหรับส่งกลับ
                userInfo.hexUuidBuffer.copy(newbuffer, 1); 
                
                newbuffer.writeInt32BE(data.readInt32BE(1), 17); // Animation/Action ID
                
                const isGlobal = data.readUInt8(5) !== 0 ? 1 : 0;
                newbuffer.writeUInt8(isGlobal, 21); // ส่ง Global Flag กลับไป
                
                if (payloadSize > 0) {
                    data.slice(6).copy(newbuffer, 22); // Payload ข้อมูลการขยับ/กดปุ่ม
                }
                
                broadcastGlobal(userInfo.uuid, newbuffer, isGlobal === 1 ? null : ws);
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

// ซิงก์รายชื่อผู้เล่นจาก Backend แบบไม่โหลดหนัก
setInterval(async () => {
    try {
        if (!API_URL || !API_KEY) return; 
        const formData = new URLSearchParams({ key: API_KEY, action: 'get_lists' });
        const res = await fastAxios.post(API_URL, formData.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }});

        if (res.data && !res.data.error && res.data.maintenance === false) {
            if (Array.isArray(res.data.blacklist)) sqlBlacklist = new Set(res.data.blacklist.map(v => String(v).toLowerCase().trim()));
            if (ENABLE_WHITELIST && Array.isArray(res.data.whitelist)) sqlWhitelist = new Set(res.data.whitelist.map(v => String(v).toLowerCase().trim()));
        }
    } catch (e) {}
}, 15000);

server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n✨ BIGAVATAR CLOUD (STABLE 1.0) ONLINE - ZONE: ${currentZone.name}\n`);
});
