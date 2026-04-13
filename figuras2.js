const express = require('express');
const http = require('http'); 
const https = require('https');
const WebSocket = require('ws');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const fsp = require('fs/promises');
const cors = require('cors');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit'); 

const c = { g: '\x1b[32m', b: '\x1b[36m', y: '\x1b[33m', r: '\x1b[31m', p: '\x1b[35m', rst: '\x1b[0m' };
const logTime = () => `[${new Date().toLocaleTimeString('th-TH')}]`;

process.on('uncaughtException', (err) => { console.log(`${c.r}[Error] ${err.message}${c.rst}`); });
process.on('unhandledRejection', (reason) => {});

// ==========================================
// ⚙️ การตั้งค่าสำหรับเซิร์ฟเวอร์ (RENTER CONFIG)
// ==========================================
const PORT = 80; 
const LIMIT_BYTES = 10 * 1024 * 1024; // ลิมิต 10MB
const ENABLE_WHITELIST = true; 

// 🌐 ใส่ลิงก์ Discord Webhook ตรงนี้ (ถ้ามี) เพื่อรับแจ้งเตือน
const DISCORD_WEBHOOK_URL = "https://ptb.discord.com/api/webhooks/1493205171088523356/kZDhTcWxPUv9NNKG035D7Er7P2tJAL9Sh14v1OjzHyE_HmYcUNcw72mFj4QkTunS8UNA"; 

// 🌐 API Bridge (ลิงก์เว็บจัดการหลัก)
const API_URL = "https://bigavatar.dpdns.org/api.php"; 

// 🔑 นำ API Key จากหน้าเว็บมาใส่ที่นี่
const API_KEY = "5de1a6c187ba4e39165c60deee6f8f0f"; 

const MOTD_MESSAGE = "§b§lขอขอบคุณที่ใช้บริการนะคับ §f§l- §a§lดูรายละเอียดเพิ่มเติมได้ที่: §e§nhttps://dash.faydar.eu.cc";
// ==========================================

const avatarsDir = path.join(__dirname, "avatars");
if (!fs.existsSync(avatarsDir)) fs.mkdirSync(avatarsDir);

const app = express();
app.set('trust proxy', 1);
app.use(cors());

// 🛡️ เพิ่มระบบ Anti-DDoS ให้ API
const apiLimiter = rateLimit({ windowMs: 1 * 60 * 1000, max: 2000, message: { error: "Too many requests." } });
app.use('/api/', apiLimiter);
app.use((req, res, next) => { if (req.url.includes('//')) req.url = req.url.replace(/\/{2,}/g, '/'); next(); });

const server_ids = new Map();
const tokens = new Map();
const tokenMap = new Map(); 
const wsMap = new Map(); 
let hashCache = new Map(); 
const spamTracker = new Map(); // ระบบแบนคนสแปมชั่วคราว

const cacheFile = path.join(__dirname, 'hashCache.json');
if (fs.existsSync(cacheFile)) {
    try { hashCache = new Map(Object.entries(JSON.parse(fs.readFileSync(cacheFile)))); } catch(e) {}
}
const saveCache = () => fs.writeFile(cacheFile, JSON.stringify(Object.fromEntries(hashCache)), () => {});

let sqlBlacklist = new Set();
let sqlWhitelist = new Set();
const userActivity = new Map(); 

const fastAxios = axios.create({
    timeout: 5000, 
    httpAgent: new http.Agent({ keepAlive: true, maxSockets: 100 }),
    httpsAgent: new https.Agent({ keepAlive: true, maxSockets: 100, rejectUnauthorized: false })
});

// ฟังก์ชันส่งข้อความเข้า Discord
function sendToDiscord(message) {
    if (!DISCORD_WEBHOOK_URL || DISCORD_WEBHOOK_URL === "") return;
    axios.post(DISCORD_WEBHOOK_URL, { content: message }).catch(() => {});
}

function formatUuid(uuid) { 
    if (!uuid || uuid.length !== 32) return uuid || "";
    return `${uuid.slice(0, 8)}-${uuid.slice(8, 12)}-${uuid.slice(12, 16)}-${uuid.slice(16, 20)}-${uuid.slice(20)}`;
}

// 🧹 เคลียร์ Memory และ ไฟล์ขยะ
setInterval(() => { 
    const now = Date.now();
    for (let [id, data] of server_ids.entries()) {
        if (now - data.time > 60000) server_ids.delete(id); 
    }
    spamTracker.clear(); // ล้างประวัติสแปมทุกๆ 5 นาที
    fs.readdir(avatarsDir, (err, files) => {
        if (err) return;
        files.forEach(file => { if (file.endsWith('.tmp')) fs.unlink(path.join(avatarsDir, file), () => {}); });
    });
}, 5 * 60 * 1000);

// ⚡ ซิงค์ข้อมูลกับเว็บ 
async function syncAndMonitor() {
    try {
        const formData = new URLSearchParams();
        formData.append('key', API_KEY);
        formData.append('action', 'get_lists');

        const res = await fastAxios.post(API_URL, formData.toString(), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        if (res.data && !res.data.error) {
            sqlBlacklist = new Set(res.data.blacklist);
            if (ENABLE_WHITELIST) sqlWhitelist = new Set(res.data.whitelist);
        }

        const onlineData = [];
        for (const [ws, tokenStr] of tokenMap.entries()) {
            const userInfo = tokens.get(tokenStr);
            if (!userInfo) continue;

            const uname = userInfo.username.toLowerCase();
            
            onlineData.push({
                name: userInfo.username,
                activity: userActivity.get(userInfo.username) || "Idle (ออนไลน์ปกติ)",
                last_size: userInfo.lastSize || 0
            });

            if (sqlBlacklist.has(uname) || (ENABLE_WHITELIST && !sqlWhitelist.has(uname))) {
                ws.terminate(); 
                tokens.delete(tokenStr);
                tokenMap.delete(ws);
                hashCache.delete(userInfo.uuid);
                saveCache();
                fsp.unlink(path.join(__dirname, 'avatars', `${userInfo.uuid}.moon`)).catch(() => {}); 
                if (wsMap.has(userInfo.uuid)) wsMap.delete(userInfo.uuid);
            }
        }
        
        if (onlineData.length > 0) {
            const hbData = new URLSearchParams();
            hbData.append('key', API_KEY);
            hbData.append('action', 'heartbeat');
            hbData.append('data', JSON.stringify(onlineData));
            fastAxios.post(API_URL, hbData.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }}).catch(()=>{});
        }

    } catch (e) {} 
}
setInterval(syncAndMonitor, 2000); 

app.get('/api/motd', (req, res) => res.status(200).send(MOTD_MESSAGE));
app.get('/api/version', (req, res) => res.json({"release":"0.1.5", "prerelease":"0.1.5"}));
app.get('/api/limits', (req, res) => res.json({"rate": { "pingSize": 1048576, "pingRate": 4096, "equip": 0, "download": 999999999999, "upload": 99999999999 }, "limits": { "maxAvatarSize": LIMIT_BYTES, "maxAvatars": 100, "allowedBadges": { "special": Array(15).fill(0), "pride": Array(30).fill(0) } }}));

app.get('/api/auth/id', (req, res) => {
    const uname = req.query.username.toLowerCase();
    if (sqlBlacklist.has(uname)) return res.status(403).send("ถูกแบนถาวร");
    if (ENABLE_WHITELIST && !sqlWhitelist.has(uname)) return res.status(403).send("ไม่มีรายชื่อในเซิร์ฟเวอร์นี้ (Not Whitelisted)");

    const serverID = crypto.randomBytes(16).toString('hex');
    server_ids.set(serverID, { username: req.query.username, time: Date.now() });
    res.send(serverID);
});

app.get('/api/auth/verify', async (req, res) => {
    try {
        const sid = req.query.id;
        const sessionData = server_ids.get(sid);
        if (!sessionData) return res.status(404).json({ error: 'Auth failed' });
        
        const response = await axios.get("https://sessionserver.mojang.com/session/minecraft/hasJoined", {
            params: { username: sessionData.username, serverId: sid }
        });
        
        server_ids.delete(sid); 
        const token = crypto.randomBytes(16).toString('hex');
        const hexUuid = response.data.id;
        const premiumUuid = formatUuid(hexUuid);
        
        tokens.set(token, { 
            uuid: premiumUuid, hexUuid: hexUuid, username: response.data.name,
            clientIp: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
            projectInfo: req.headers['user-agent'] || 'Unknown Tool',
            lastSize: 0
        });
        
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
        wsMap.get(userInfo.uuid).forEach(ws => { if (ws.readyState === WebSocket.OPEN) ws.send(buffer); });
    }
    res.send("success");
});

app.put('/api/avatar', (req, res) => {
    const userInfo = tokens.get(req.headers['token']);
    if (!userInfo) return res.status(401).end();
    
    let contentLength = parseInt(req.headers['content-length'] || '0');
    userInfo.lastSize = contentLength;
    
    // 🛡️ ระบบแบนคนสแปมชั่วคราว
    if (contentLength > LIMIT_BYTES) {
        userActivity.set(userInfo.username, "❌ สแปมไฟล์ใหญ่เกิน!");
        let strikes = (spamTracker.get(userInfo.username) || 0) + 1;
        spamTracker.set(userInfo.username, strikes);
        
        if (strikes >= 3) {
            sendToDiscord(`🚨 **[ระบบป้องกัน]** \`${userInfo.username}\` พยายามอัปโหลดไฟล์เกิน 10MB รัวๆ (โดนเตะชั่วคราว)`);
            sqlBlacklist.add(userInfo.username.toLowerCase()); // แบนเข้า Blacklist สดๆ ทันที
        }
        return res.status(413).end();
    }

    userActivity.set(userInfo.username, "📤 กำลังอัปโหลดโมเดล...");
    const tempFile = path.join(__dirname, 'avatars', `${userInfo.uuid}.moon.tmp`);
    const finalFile = path.join(__dirname, 'avatars', `${userInfo.uuid}.moon`);
    const writeStream = fs.createWriteStream(tempFile);
    const hash = crypto.createHash('sha256');

    req.on('data', chunk => { hash.update(chunk); writeStream.write(chunk); });
    req.on('end', () => writeStream.end());
    req.on('aborted', () => { writeStream.destroy(); fsp.unlink(tempFile).catch(()=>{}); });

    writeStream.on('finish', async () => {
        try {
            await fsp.rename(tempFile, finalFile);
            hashCache.set(userInfo.uuid, hash.digest('hex')); 
            saveCache(); 
            userActivity.set(userInfo.username, "✅ อัปโหลดสำเร็จ!");
            if (wsMap.has(userInfo.uuid)) {
                const buffer = Buffer.allocUnsafe(17); buffer.writeUInt8(2, 0); Buffer.from(userInfo.hexUuid, 'hex').copy(buffer, 1);
                wsMap.get(userInfo.uuid).forEach(ws => { if (ws.readyState === WebSocket.OPEN) ws.send(buffer); });
            }
            res.send("success"); 
        } catch (err) { res.status(500).send({ error: "File error" }); }
    });
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
            wsMap.get(userInfo.uuid).forEach(ws => { if (ws.readyState === WebSocket.OPEN) ws.send(buffer); });
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
    if (["motd", "version", "auth", "limits", "stats-secret"].includes(uuidStr)) return res.status(404).end();
    const uuid = formatUuid(uuidStr);
    if (!uuid) return res.status(404).end();

    const data = { uuid: uuid, rank: "normal", equipped: [], lastUsed: new Date().toISOString(), equippedBadges: { special: Array(15).fill(0), pride: Array(30).fill(0) }, version: "0.1.5", banned: false };
    let fileHash = hashCache.get(uuid);
    const avatarFile = path.join(__dirname, 'avatars', `${uuid}.moon`);
    
    if (!fileHash) {
        try {
            await fsp.access(avatarFile);
            const fileBuffer = await fsp.readFile(avatarFile);
            fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
            hashCache.set(uuid, fileHash);
            saveCache();
        } catch (e) {}
    }
    if (fileHash) data.equipped.push({ id: 'avatar', owner: uuid, hash: fileHash });
    res.json(data);
});

app.get('/', (req, res) => { res.status(200).send(MOTD_MESSAGE); });

// ==========================================
// ⚡ WEBSOCKET (ระบบ Anti-Drop สมบูรณ์แบบ)
// ==========================================
const server = http.createServer(app);
server.keepAliveTimeout = 120000; 
server.headersTimeout = 125000;

const wss = new WebSocket.Server({ server, perMessageDeflate: false });

wss.on('connection', (ws) => {
    ws.on('message', (data) => {
        try {
            if (data.length > LIMIT_BYTES + 5000000) return; 

            if (Buffer.isBuffer(data)) {
                const type = data[0];
                if (type === 0) {
                    tokenMap.set(ws, data.slice(1).toString('utf-8'));
                    if (ws.readyState === WebSocket.OPEN) ws.send(Buffer.from([0]));
                }
                else if (type === 1) { 
                    const userInfo = tokens.get(tokenMap.get(ws));
                    if (!userInfo) return;
                    
                    const dataLen = data.length;
                    const newbuffer = Buffer.allocUnsafe(22 + (dataLen - 6));
                    newbuffer.writeUInt8(0, 0); Buffer.from(userInfo.hexUuid, 'hex').copy(newbuffer, 1); 
                    newbuffer.writeInt32BE(data.readInt32BE(1), 17); newbuffer.writeUInt8(data.readUInt8(5) !== 0 ? 1 : 0, 21); 
                    data.slice(6).copy(newbuffer, 22);
                    
                    const connections = wsMap.get(userInfo.uuid);
                    if (connections) { connections.forEach(tws => { if (tws.readyState === WebSocket.OPEN && (newbuffer.readUInt8(21) === 1 || tws !== ws)) tws.send(newbuffer); }); }
                }
                else if (type === 2 || type === 3) {
                    const uuidHex = data.slice(1, 17).toString('hex');
                    const uuid = formatUuid(uuidHex);
                    if (type === 2) { if (!wsMap.has(uuid)) wsMap.set(uuid, new Set()); wsMap.get(uuid).add(ws); 
                    } else { if (wsMap.has(uuid)) wsMap.get(uuid).delete(ws); }
                }
            }
        } catch (e) {} 
    });
    
    ws.on('error', () => {}); 
    ws.on('close', () => {
        const token = tokenMap.get(ws);
        if (token && tokens.has(token)) {
            const uuid = tokens.get(token).uuid;
            if (wsMap.has(uuid)) { wsMap.get(uuid).delete(ws); if (wsMap.get(uuid).size === 0) wsMap.delete(uuid); }
        }
        tokenMap.delete(ws);
    });
});

const interval = setInterval(() => { wss.clients.forEach((ws) => { if (ws.readyState === WebSocket.OPEN) ws.ping(); }); }, 5000); 
wss.on('close', () => clearInterval(interval));

server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n${c.p}==========================================${c.rst}`);
    console.log(`${c.b}🚀 BIGAVTAR CLOUD - GOD TIER V6${c.rst}`);
    console.log(`${c.g}✅ API Link: ${API_URL}${c.rst}`);
    console.log(`${c.g}✅ Protection & Webhooks Active!${c.rst}`);
    console.log(`${c.p}==========================================${c.rst}\n`);
    sendToDiscord("✅ **[ระบบเปิดใช้งาน]** เซิร์ฟเวอร์ Figura (V6) ออนไลน์แล้ว!");
});
