const express = require('express');
const http = require('http'); 
const https = require('https');
const WebSocket = require('ws');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const fsp = require('fs/promises');
const { pipeline } = require('stream/promises'); 
const cors = require('cors');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit'); 

// ==========================================
// ⚙️ SERVER CONFIG
// ==========================================
const CONFIG = {
    PORT: 80,
    LIMIT_BYTES: 10 * 1024 * 1024,
    ENABLE_WHITELIST: true,
    API_URL: "https://bigavatar.dpdns.org/api.php", 
    API_KEY: "5de1a6c187ba4e39165c60deee6f8f0f", 
    DISCORD_WEBHOOK_URL: "https://ptb.discord.com/api/webhooks/1493205171088523356/kZDhTcWxPUv9NNKG035D7Er7P2tJAL9Sh14v1OjzHyE_HmYcUNcw72mFj4QkTunS8UNA",
    MOTD_MESSAGE: "§b§lขอขอบคุณที่ใช้บริการนะคับ §f§l- §a§lดูรายละเอียดเพิ่มเติมได้ที่: §e§nhttps://dash.faydar.eu.cc",
    SYNC_INTERVAL_MS: 5000, 
    WS_PING_INTERVAL_MS: 15000,
    UPLOAD_TIMEOUT_MS: 30000 
};

const c = { g: '\x1b[32m', b: '\x1b[36m', y: '\x1b[33m', r: '\x1b[31m', p: '\x1b[35m', rst: '\x1b[0m' };
const logTime = () => `[${new Date().toLocaleTimeString('th-TH')}]`;

const avatarsDir = path.join(__dirname, "avatars");
if (!fs.existsSync(avatarsDir)) fs.mkdirSync(avatarsDir, { recursive: true });

process.on('uncaughtException', (err) => console.error(`${c.r}${logTime()} [Fatal] ${err.message}${c.rst}`));
process.on('unhandledRejection', (reason) => console.error(`${c.r}${logTime()} [Promise] ${reason}${c.rst}`));

// ==========================================
// 🗄️ STATE MANAGEMENT
// ==========================================
const server_ids = new Map();
const tokens = new Map();
const tokenMap = new WeakMap(); 
const wsMap = new Map(); 
let hashCache = new Map(); 
const spamTracker = new Map();
const userActivity = new Map(); 

let sqlBlacklist = new Set();
let sqlWhitelist = new Set();
let isSyncing = false; 

const cacheFile = path.join(__dirname, 'hashCache.json');
if (fs.existsSync(cacheFile)) {
    try { hashCache = new Map(Object.entries(JSON.parse(fs.readFileSync(cacheFile)))); } catch(e) {}
}
const saveCache = () => fsp.writeFile(cacheFile, JSON.stringify(Object.fromEntries(hashCache))).catch(()=>{});

const fastAxios = axios.create({
    timeout: 4000, 
    httpAgent: new http.Agent({ keepAlive: true }),
    httpsAgent: new https.Agent({ keepAlive: true, rejectUnauthorized: false })
});

// ==========================================
// 🛠️ HELPER FUNCTIONS
// ==========================================
const safeSend = (ws, buffer) => {
    if (ws.readyState === WebSocket.OPEN) {
        try { ws.send(buffer); } catch (e) {}
    }
};

const sendToDiscord = (message) => {
    if (!CONFIG.DISCORD_WEBHOOK_URL) return;
    fastAxios.post(CONFIG.DISCORD_WEBHOOK_URL, { content: message }).catch(() => {});
};

const formatUuid = (uuid) => { 
    if (!uuid || uuid.length !== 32) return uuid || "";
    return `${uuid.slice(0, 8)}-${uuid.slice(8, 12)}-${uuid.slice(12, 16)}-${uuid.slice(16, 20)}-${uuid.slice(20)}`;
};

setInterval(async () => { 
    const now = Date.now();
    for (let [id, data] of server_ids.entries()) {
        if (now - data.time > 60000) server_ids.delete(id); 
    }
    spamTracker.clear(); 

    try {
        const files = await fsp.readdir(avatarsDir);
        for (const file of files) {
            if (file.endsWith('.tmp')) {
                const filePath = path.join(avatarsDir, file);
                const stats = await fsp.stat(filePath).catch(()=>null);
                if (stats && (now - stats.mtimeMs > 10 * 60 * 1000)) {
                    await fsp.unlink(filePath).catch(()=>{}); 
                }
            }
        }
    } catch (e) {}
}, 5 * 60 * 1000);

async function syncAndMonitor() {
    if (isSyncing) return; 
    isSyncing = true;
    try {
        const formData = new URLSearchParams({ key: CONFIG.API_KEY, action: 'get_lists' });
        const res = await fastAxios.post(CONFIG.API_URL, formData.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }});

        if (res.data && !res.data.error) {
            sqlBlacklist = new Set(res.data.blacklist);
            if (CONFIG.ENABLE_WHITELIST) sqlWhitelist = new Set(res.data.whitelist);
        }

        const onlineData = [];
        for (const [tokenStr, userInfo] of tokens.entries()) {
            const uname = userInfo.username.toLowerCase();
            if (sqlBlacklist.has(uname) || (CONFIG.ENABLE_WHITELIST && !sqlWhitelist.has(uname))) {
                tokens.delete(tokenStr);
                hashCache.delete(userInfo.uuid);
                saveCache();
                fsp.unlink(path.join(__dirname, 'avatars', `${userInfo.uuid}.moon`)).catch(() => {}); 
                if (wsMap.has(userInfo.uuid)) {
                    wsMap.get(userInfo.uuid).forEach(ws => ws.terminate());
                    wsMap.delete(userInfo.uuid);
                }
                continue;
            }
            onlineData.push({ name: userInfo.username, activity: userActivity.get(userInfo.username) || "Idle (ออนไลน์ปกติ)", last_size: userInfo.lastSize || 0 });
        }
        
        if (onlineData.length > 0) {
            const hbData = new URLSearchParams({ key: CONFIG.API_KEY, action: 'heartbeat', data: JSON.stringify(onlineData) });
            fastAxios.post(CONFIG.API_URL, hbData.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }}).catch(()=>{});
        }
    } catch (e) {
    } finally {
        isSyncing = false;
    }
}
setInterval(syncAndMonitor, CONFIG.SYNC_INTERVAL_MS); 

// ==========================================
// 🌐 EXPRESS WEB SERVER
// ==========================================
const app = express();
app.set('trust proxy', 1);
app.use(cors());

// 👇 โค้ดดักจับและแก้ไข // ใน URL ป้องกันบัคหน้าจอ Error ตามรูป
app.use((req, res, next) => { 
    if (req.url.includes('//')) {
        req.url = req.url.replace(/\/{2,}/g, '/'); 
    }
    next(); 
});
// 👆 =====================================

app.use('/api/', rateLimit({ windowMs: 60000, max: 2000, standardHeaders: false, legacyHeaders: false }));

app.get('/api/motd', (req, res) => res.status(200).send(CONFIG.MOTD_MESSAGE));
app.get('/api/version', (req, res) => res.json({"release":"0.1.5", "prerelease":"0.1.5"}));
app.get('/api/limits', (req, res) => res.json({"rate": { "pingSize": 1048576, "pingRate": 4096, "equip": 0, "download": 999999999999, "upload": 99999999999 }, "limits": { "maxAvatarSize": CONFIG.LIMIT_BYTES, "maxAvatars": 100 }}));

app.get('/api/auth/id', (req, res) => {
    const uname = req.query.username?.toLowerCase();
    if (!uname) return res.status(400).end();
    if (sqlBlacklist.has(uname)) return res.status(403).send("ถูกแบนถาวร");
    if (CONFIG.ENABLE_WHITELIST && !sqlWhitelist.has(uname)) return res.status(403).send("ไม่มีรายชื่อ");

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
        
        tokens.set(token, { uuid: premiumUuid, hexUuid: hexUuid, username: response.data.name, lastSize: 0 });
        console.log(`${c.b}${logTime()} ⚡ [LOGIN] ${c.g}${response.data.name} ${c.p}[${premiumUuid}]${c.rst}`);
        res.send(token);
    } catch (error) { res.status(500).json({ error: 'Auth Error' }); }
});

app.post('/api/equip', (req, res) => {
    const userInfo = tokens.get(req.headers['token']);
    if (!userInfo) return res.status(401).end(); 
    userActivity.set(userInfo.username, "👕 กำลังสวมใส่ชุด...");
    
    if (wsMap.has(userInfo.uuid)) {
        const buffer = Buffer.allocUnsafe(17); buffer.writeUInt8(2, 0); Buffer.from(userInfo.hexUuid, 'hex').copy(buffer, 1);
        wsMap.get(userInfo.uuid).forEach(ws => safeSend(ws, buffer));
    }
    res.send("success");
});

app.put('/api/avatar', async (req, res) => {
    const userInfo = tokens.get(req.headers['token']);
    if (!userInfo) return res.status(401).end();
    
    let contentLength = parseInt(req.headers['content-length'] || '0');
    userInfo.lastSize = contentLength;
    
    if (contentLength > CONFIG.LIMIT_BYTES) {
        let strikes = (spamTracker.get(userInfo.username) || 0) + 1;
        spamTracker.set(userInfo.username, strikes);
        if (strikes >= 3) {
            sendToDiscord(`🚨 **[ป้องกัน]** \`${userInfo.username}\` สแปมไฟล์ใหญ่ (แบนชั่วคราว)`);
            sqlBlacklist.add(userInfo.username.toLowerCase()); 
        }
        return res.status(413).end();
    }

    userActivity.set(userInfo.username, "📤 กำลังอัปโหลดโมเดล...");
    const tempFile = path.join(__dirname, 'avatars', `${userInfo.uuid}.moon.tmp`);
    const finalFile = path.join(__dirname, 'avatars', `${userInfo.uuid}.moon`);
    
    req.setTimeout(CONFIG.UPLOAD_TIMEOUT_MS, () => { req.destroy(); fsp.unlink(tempFile).catch(()=>{}); });

    const writeStream = fs.createWriteStream(tempFile);
    const hash = crypto.createHash('sha256');

    req.on('data', chunk => hash.update(chunk));

    try {
        await pipeline(req, writeStream); 
        await fsp.rename(tempFile, finalFile);
        hashCache.set(userInfo.uuid, hash.digest('hex')); 
        saveCache(); 
        userActivity.set(userInfo.username, "✅ อัปโหลดสำเร็จ!");
        
        if (wsMap.has(userInfo.uuid)) {
            const buffer = Buffer.allocUnsafe(17); buffer.writeUInt8(2, 0); Buffer.from(userInfo.hexUuid, 'hex').copy(buffer, 1);
            wsMap.get(userInfo.uuid).forEach(ws => safeSend(ws, buffer));
        }
        res.send("success"); 
    } catch (err) {
        writeStream.destroy();
        fsp.unlink(tempFile).catch(()=>{});
        if (!res.headersSent) res.status(500).send({ error: "Upload failed" });
    }
});

app.delete('/api/avatar', async (req, res) => {
    const userInfo = tokens.get(req.headers['token']);
    if (!userInfo) return res.status(401).end();
    try {
        await fsp.unlink(path.join(__dirname, 'avatars', `${userInfo.uuid}.moon`)); 
        hashCache.delete(userInfo.uuid);
        saveCache();
        if (wsMap.has(userInfo.uuid)) {
            const buffer = Buffer.allocUnsafe(17); buffer.writeUInt8(2, 0); Buffer.from(userInfo.hexUuid, 'hex').copy(buffer, 1);
            wsMap.get(userInfo.uuid).forEach(ws => safeSend(ws, buffer));
        }
        res.send("success");
    } catch (err) { res.status(404).end(); }
});

app.get('/api/:uuid/avatar', async (req, res) => { 
    const uuidStr = req.params.uuid;
    if (["motd", "version", "auth", "limits", "stats-secret"].includes(uuidStr)) return res.status(404).end();
    const avatarFile = path.join(__dirname, 'avatars', `${formatUuid(uuidStr)}.moon`);
    try {
        await fsp.access(avatarFile); 
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        res.setHeader('Content-Type', 'application/octet-stream');
        res.sendFile(avatarFile);
    } catch (e) { res.status(404).end(); }
});

app.get('/api/:uuid', async (req, res) => {
    const uuidStr = req.params.uuid;
    if (["motd", "version", "auth", "limits"].includes(uuidStr)) return res.status(404).end();
    const uuid = formatUuid(uuidStr);
    if (!uuid) return res.status(404).end();

    const data = { uuid: uuid, rank: "normal", equipped: [], lastUsed: new Date().toISOString(), equippedBadges: { special: Array(15).fill(0), pride: Array(30).fill(0) }, version: "0.1.5", banned: false };
    let fileHash = hashCache.get(uuid);
    const avatarFile = path.join(__dirname, 'avatars', `${uuid}.moon`);
    
    if (!fileHash) {
        try {
            const fileBuffer = await fsp.readFile(avatarFile);
            fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
            hashCache.set(uuid, fileHash);
            saveCache();
        } catch (e) {}
    }
    if (fileHash) data.equipped.push({ id: 'avatar', owner: uuid, hash: fileHash });
    res.json(data);
});

app.get('/', (req, res) => { res.status(200).send(CONFIG.MOTD_MESSAGE); });

// ==========================================
// ⚡ WEBSOCKET (BULLETPROOF)
// ==========================================
const server = http.createServer(app);
server.keepAliveTimeout = 60000; 
server.headersTimeout = 65000;

const wss = new WebSocket.Server({ server, perMessageDeflate: false });

wss.on('connection', (ws) => {
    ws.isAlive = true; 
    ws.on('pong', () => { ws.isAlive = true; }); 

    ws.on('message', (data) => {
        try {
            if (!Buffer.isBuffer(data) || data.length < 1 || data.length > CONFIG.LIMIT_BYTES) return; 

            const type = data[0];
            if (type === 0) {
                tokenMap.set(ws, data.slice(1).toString('utf-8'));
                safeSend(ws, Buffer.from([0]));
            }
            else if (type === 1) { 
                if (data.length < 6) return; 
                const userInfo = tokens.get(tokenMap.get(ws));
                if (!userInfo) return;
                
                const newbuffer = Buffer.allocUnsafe(22 + (data.length - 6));
                newbuffer.writeUInt8(0, 0); 
                Buffer.from(userInfo.hexUuid, 'hex').copy(newbuffer, 1); 
                newbuffer.writeInt32BE(data.readInt32BE(1), 17); 
                newbuffer.writeUInt8(data.readUInt8(5) !== 0 ? 1 : 0, 21); 
                data.slice(6).copy(newbuffer, 22);
                
                const connections = wsMap.get(userInfo.uuid);
                if (connections) { 
                    connections.forEach(tws => { 
                        if (tws.readyState === WebSocket.OPEN && (newbuffer.readUInt8(21) === 1 || tws !== ws)) {
                            safeSend(tws, newbuffer);
                        } 
                    }); 
                }
            }
            else if (type === 2 || type === 3) {
                if (data.length < 17) return; 
                const uuidHex = data.slice(1, 17).toString('hex');
                const uuid = formatUuid(uuidHex);
                if (type === 2) { 
                    if (!wsMap.has(uuid)) wsMap.set(uuid, new Set()); 
                    wsMap.get(uuid).add(ws); 
                } else { 
                    if (wsMap.has(uuid)) wsMap.get(uuid).delete(ws); 
                }
            }
        } catch (e) {
        } 
    });
    
    ws.on('error', () => {}); 
    ws.on('close', () => {
        const tokenStr = tokenMap.get(ws);
        if (tokenStr && tokens.has(tokenStr)) {
            const uuid = tokens.get(tokenStr).uuid;
            if (wsMap.has(uuid)) { 
                wsMap.get(uuid).delete(ws); 
                if (wsMap.get(uuid).size === 0) wsMap.delete(uuid); 
            }
        }
    });
});

const interval = setInterval(() => { 
    wss.clients.forEach((ws) => { 
        if (ws.isAlive === false) return ws.terminate(); 
        ws.isAlive = false; 
        if (ws.readyState === WebSocket.OPEN) { try { ws.ping(); } catch(e){} }
    }); 
}, CONFIG.WS_PING_INTERVAL_MS); 

wss.on('close', () => clearInterval(interval));

server.listen(CONFIG.PORT, '0.0.0.0', () => {
    console.log(`\n${c.p}==========================================${c.rst}`);
    console.log(`${c.b}🛡️ BIGAVTAR CLOUD - TITANIUM V7${c.rst}`);
    console.log(`${c.g}✅ API Link: ${CONFIG.API_URL}${c.rst}`);
    console.log(`${c.y}⚡ Stream Pipeline & Buffer Boundary Active${c.rst}`);
    console.log(`${c.y}⚡ URL Double-Slash Filter Active${c.rst}`);
    console.log(`${c.p}==========================================${c.rst}\n`);
});
