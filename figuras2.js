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

const c = { g: '\x1b[32m', b: '\x1b[36m', y: '\x1b[33m', r: '\x1b[31m', p: '\x1b[35m', rst: '\x1b[0m' };
const logTime = () => `[${new Date().toLocaleTimeString('th-TH')}]`;
const startTime = Date.now();

process.on('uncaughtException', (err) => { console.log(`${c.r}[Error] ${err.message}${c.rst}`); });
process.on('unhandledRejection', (reason) => { console.log(`${c.r}[Unhandled Promise] ${reason}${c.rst}`); });

// ==========================================
// ⚙️ SERVER CONFIG (ULTRA STABLE & ANTI-DROP)
// ==========================================
const PORT = 80; 
const LIMIT_BYTES = 10 * 1024 * 1024; 
const ENABLE_WHITELIST = true; 

const DISCORD_WEBHOOK_URL = "https://ptb.discord.com/api/webhooks/1493205171088523356/kZDhTcWxPUv9NNKG035D7Er7P2tJAL9Sh14v1OjzHyE_HmYcUNcw72mFj4QkTunS8UNA"; 
const API_URL = "https://bigavatar.dpdns.org/api.php"; 
const API_KEY = "de2bf0189267191a334070ef5e960519"; 

// 🎨 [อัปเกรด] ข้อความ MOTD สวยงาม พรีเมียม และอ่านง่ายขึ้น
const MOTD_MESSAGE = "§b§l★ §3§lBIGAVATAR §f§lCLOUD §b§l★\n§a✅ §aเชื่อมต่อเซิร์ฟเวอร์เสถียรระดับสูงสุดสำเร็จ!\n§e🔗 §eจัดการโมเดลของคุณได้ที่: §nhttps://dash.faydar.eu.cc";

// ⚡ ค่าที่ปรับจูนเพื่อแก้ปัญหา Cloud Disconnected (ขีดหลุดบ่อย)
const SYNC_INTERVAL_MS = 10000;    
const WS_PING_INTERVAL_MS = 15000; 
const UPLOAD_TIMEOUT_MS = 30000;   
const DASHBOARD_PASS = "admin123"; 
// ==========================================

const avatarsDir = path.join(__dirname, "avatars");
if (!fs.existsSync(avatarsDir)) fs.mkdirSync(avatarsDir, { recursive: true });

const app = express();
app.set('trust proxy', 1);
app.use(cors());

// 🛡️ แก้ไขปัญหา // ซ้อนกันใน URL
app.use((req, res, next) => { 
    if (req.url.includes('//')) req.url = req.url.replace(/\/{2,}/g, '/'); 
    next(); 
});

const apiLimiter = rateLimit({ windowMs: 1 * 60 * 1000, max: 2000, message: { error: "Too many requests." } });
app.use('/api/', apiLimiter);

// ==========================================
// 🗄️ STATE MANAGEMENT & DATABASE
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
let isMaintenanceMode = false; 

// 💾 Local Database สำหรับสถิติ
const dbFile = path.join(__dirname, 'statsDB.json');
let serverStats = { totalLogins: 0, totalUploads: 0, totalBytes: 0 };
if (fs.existsSync(dbFile)) { try { serverStats = JSON.parse(fs.readFileSync(dbFile)); } catch(e) {} }
const saveStatsDB = () => fsp.writeFile(dbFile, JSON.stringify(serverStats)).catch(()=>{});

const cacheFile = path.join(__dirname, 'hashCache.json');
if (fs.existsSync(cacheFile)) { try { hashCache = new Map(Object.entries(JSON.parse(fs.readFileSync(cacheFile)))); } catch(e) {} }
const saveCache = () => fsp.writeFile(cacheFile, JSON.stringify(Object.fromEntries(hashCache))).catch(()=>{});

const fastAxios = axios.create({
    timeout: 8000, 
    httpAgent: new http.Agent({ keepAlive: true }),
    httpsAgent: new https.Agent({ keepAlive: true, rejectUnauthorized: false })
});

const safeSend = (ws, buffer) => { if (ws.readyState === WebSocket.OPEN) { try { ws.send(buffer); } catch (e) {} } };
const sendToDiscord = (message) => { if (!DISCORD_WEBHOOK_URL) return; fastAxios.post(DISCORD_WEBHOOK_URL, { content: message }).catch(() => {}); };
const formatUuid = (uuid) => { 
    if (!uuid || uuid.length !== 32) return uuid || "";
    return `${uuid.slice(0, 8)}-${uuid.slice(8, 12)}-${uuid.slice(12, 16)}-${uuid.slice(16, 20)}-${uuid.slice(20)}`;
};

setInterval(async () => { 
    const now = Date.now();
    for (let [id, data] of server_ids.entries()) { if (now - data.time > 60000) server_ids.delete(id); }
    spamTracker.clear(); 
    saveStatsDB(); 
    try {
        const files = await fsp.readdir(avatarsDir);
        for (const file of files) {
            if (file.endsWith('.tmp')) {
                const filePath = path.join(avatarsDir, file);
                const stats = await fsp.stat(filePath).catch(()=>null);
                if (stats && (now - stats.mtimeMs > 10 * 60 * 1000)) { await fsp.unlink(filePath).catch(()=>{}); }
            }
        }
    } catch (e) {}
}, 5 * 60 * 1000);

// ⚡ ระบบ Sync (แยกระบบ Maintenance Mode ชัดเจน)
async function syncAndMonitor() {
    if (isSyncing) return; 
    isSyncing = true;
    try {
        const formData = new URLSearchParams({ key: API_KEY, action: 'get_lists' });
        const res = await fastAxios.post(API_URL, formData.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }});

        if (res.data && res.data.maintenance === true) {
            isMaintenanceMode = true;
        } else {
            isMaintenanceMode = false;
            if (res.data && !res.data.error) {
                sqlBlacklist = new Set(res.data.blacklist || []);
                if (ENABLE_WHITELIST && res.data.whitelist) sqlWhitelist = new Set(res.data.whitelist || []);
            }
        }

        const onlineData = [];
        for (const [tokenStr, userInfo] of tokens.entries()) {
            const uname = userInfo.username.toLowerCase();
            
            if (isMaintenanceMode) {
                tokens.delete(tokenStr);
                if (wsMap.has(userInfo.uuid)) { wsMap.get(userInfo.uuid).forEach(ws => ws.terminate()); wsMap.delete(userInfo.uuid); }
                continue;
            }

            if (sqlBlacklist.has(uname) || (ENABLE_WHITELIST && !sqlWhitelist.has(uname))) {
                tokens.delete(tokenStr);
                hashCache.delete(userInfo.uuid);
                saveCache();
                fsp.unlink(path.join(__dirname, 'avatars', `${userInfo.uuid}.moon`)).catch(() => {}); 
                if (wsMap.has(userInfo.uuid)) { wsMap.get(userInfo.uuid).forEach(ws => ws.terminate()); wsMap.delete(userInfo.uuid); }
                continue;
            }
            onlineData.push({ name: userInfo.username, activity: userActivity.get(userInfo.username) || "Idle (ออนไลน์ปกติ)", last_size: userInfo.lastSize || 0 });
        }
        
        if (onlineData.length > 0 && !isMaintenanceMode) {
            const hbData = new URLSearchParams({ key: API_KEY, action: 'heartbeat', data: JSON.stringify(onlineData) });
            fastAxios.post(API_URL, hbData.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }}).catch(()=>{});
        }
    } catch (e) {
    } finally {
        isSyncing = false;
    }
}
setInterval(syncAndMonitor, SYNC_INTERVAL_MS); 

// ==========================================
// 🌐 API ROUTES & DASHBOARD
// ==========================================
app.get('/api/server-stats', (req, res) => {
    if (req.query.pass !== DASHBOARD_PASS) return res.status(403).json({ error: "Unauthorized" });
    const uptimeSecs = Math.floor((Date.now() - startTime) / 1000);
    res.json({
        onlinePlayers: tokens.size, totalLogins: serverStats.totalLogins, totalUploads: serverStats.totalUploads,
        totalBytesMB: (serverStats.totalBytes / 1024 / 1024).toFixed(2), ramUsageMB: (process.memoryUsage().rss / 1024 / 1024).toFixed(2),
        uptimeStr: `${Math.floor(uptimeSecs/3600)}h ${Math.floor((uptimeSecs%3600)/60)}m ${uptimeSecs%60}s`
    });
});

app.get('/dashboard', (req, res) => {
    if (req.query.pass !== DASHBOARD_PASS) return res.send(`<h2>Access Denied.</h2>`);
    res.send(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>BigAvatar Cloud - Dashboard</title><script src="https://cdn.tailwindcss.com"></script><style>body { background-color: #0f172a; color: #f8fafc; font-family: 'Inter', sans-serif; } .glass { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1); } .glow-text { text-shadow: 0 0 10px rgba(56, 189, 248, 0.5); }</style></head><body class="min-h-screen p-8"><div class="max-w-5xl mx-auto"><header class="mb-10 text-center"><h1 class="text-4xl font-bold text-sky-400 glow-text mb-2">🚀 BIGAVATAR CLOUD</h1><p class="text-slate-400">V10 Ultimate - Server Monitor</p></header><div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8"><div class="glass rounded-2xl p-6 text-center transform transition hover:scale-105"><h3 class="text-slate-400 font-medium mb-1">🟢 Online Players</h3><p id="s-online" class="text-5xl font-bold text-emerald-400">0</p></div><div class="glass rounded-2xl p-6 text-center transform transition hover:scale-105"><h3 class="text-slate-400 font-medium mb-1">⚡ RAM Usage</h3><p id="s-ram" class="text-5xl font-bold text-amber-400">0 MB</p></div><div class="glass rounded-2xl p-6 text-center transform transition hover:scale-105"><h3 class="text-slate-400 font-medium mb-1">⏱️ Uptime</h3><p id="s-uptime" class="text-4xl font-bold text-sky-400 mt-2">0h 0m 0s</p></div><div class="glass rounded-2xl p-6 text-center transform transition hover:scale-105"><h3 class="text-slate-400 font-medium mb-1">👥 Total Logins</h3><p id="s-logins" class="text-4xl font-bold text-fuchsia-400 mt-2">0</p></div><div class="glass rounded-2xl p-6 text-center transform transition hover:scale-105"><h3 class="text-slate-400 font-medium mb-1">📤 Models Uploaded</h3><p id="s-uploads" class="text-4xl font-bold text-indigo-400 mt-2">0</p></div><div class="glass rounded-2xl p-6 text-center transform transition hover:scale-105"><h3 class="text-slate-400 font-medium mb-1">💾 Data Transferred</h3><p id="s-bytes" class="text-4xl font-bold text-rose-400 mt-2">0 MB</p></div></div><div class="text-center text-slate-500 text-sm mt-10">Auto-refreshing every 3 seconds</div></div><script> const urlParams = new URLSearchParams(window.location.search); const pass = urlParams.get('pass'); async function fetchStats() { try { const res = await fetch('/api/server-stats?pass=' + pass); const data = await res.json(); if(data.error) return; document.getElementById('s-online').innerText = data.onlinePlayers; document.getElementById('s-ram').innerText = data.ramUsageMB + ' MB'; document.getElementById('s-uptime').innerText = data.uptimeStr; document.getElementById('s-logins').innerText = data.totalLogins.toLocaleString(); document.getElementById('s-uploads').innerText = data.totalUploads.toLocaleString(); document.getElementById('s-bytes').innerText = data.totalBytesMB + ' MB'; } catch(e) {} } fetchStats(); setInterval(fetchStats, 3000); </script></body></html>`);
});

app.get('/api/motd', (req, res) => res.status(200).send(MOTD_MESSAGE));
app.get('/api/version', (req, res) => res.json({"release":"0.1.5", "prerelease":"0.1.5"}));

// ✅ [สมบูรณ์] คืนค่า allowedBadges กัน Mod หาไม่เจอ
app.get('/api/limits', (req, res) => res.json({"rate": { "pingSize": 1048576, "pingRate": 4096, "equip": 0, "download": 999999999999, "upload": 99999999999 }, "limits": { "maxAvatarSize": LIMIT_BYTES, "maxAvatars": 100, "allowedBadges": { "special": Array(15).fill(0), "pride": Array(30).fill(0) } }}));

app.get('/api/auth/id', (req, res) => {
    const uname = req.query.username?.toLowerCase();
    if (!uname) return res.status(400).end();

    if (isMaintenanceMode) return res.status(403).send("§e⚠ เซิร์ฟเวอร์อยู่ในโหมดปิดปรับปรุง (Maintenance)");
    
    if (sqlBlacklist.has(uname)) return res.status(403).send("ถูกแบนถาวร");
    if (ENABLE_WHITELIST && !sqlWhitelist.has(uname)) return res.status(403).send("ไม่มีรายชื่อ");

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

        // ✅ [สมบูรณ์] คืนค่า clientIp และ projectInfo สำหรับเก็บสถิติ
        tokens.set(token, { 
            uuid: premiumUuid, hexUuid: hexUuid, hexUuidBuffer: hexUuidBuffer, username: response.data.name, 
            clientIp: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
            projectInfo: req.headers['user-agent'] || 'Unknown Tool',
            lastSize: 0 
        });
        
        serverStats.totalLogins++;
        saveStatsDB();

        console.log(`${c.b}${logTime()} ⚡ [LOGIN] ${c.g}${response.data.name} ${c.p}[${premiumUuid}]${c.rst}`);
        res.send(token);
    } catch (error) { res.status(500).json({ error: 'Auth Error' }); }
});

app.post('/api/equip', (req, res) => {
    const userInfo = tokens.get(req.headers['token']);
    if (!userInfo) return res.status(401).end(); 
    userActivity.set(userInfo.username, "👕 กำลังสวมใส่ชุด...");
    
    if (wsMap.has(userInfo.uuid)) {
        const buffer = Buffer.allocUnsafe(17); buffer.writeUInt8(2, 0); 
        userInfo.hexUuidBuffer.copy(buffer, 1); 
        wsMap.get(userInfo.uuid).forEach(ws => safeSend(ws, buffer));
    }
    res.send("success");
});

app.put('/api/avatar', async (req, res) => {
    const userInfo = tokens.get(req.headers['token']);
    if (!userInfo) return res.status(401).end();
    
    let contentLength = parseInt(req.headers['content-length'] || '0');
    userInfo.lastSize = contentLength;
    
    if (contentLength > LIMIT_BYTES) {
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
    
    req.setTimeout(UPLOAD_TIMEOUT_MS, () => { req.destroy(); fsp.unlink(tempFile).catch(()=>{}); });

    const writeStream = fs.createWriteStream(tempFile);
    const hash = crypto.createHash('sha256');
    req.on('data', chunk => hash.update(chunk));

    try {
        await pipeline(req, writeStream); 
        await fsp.rename(tempFile, finalFile);
        hashCache.set(userInfo.uuid, hash.digest('hex')); 
        saveCache(); 

        serverStats.totalUploads++;
        serverStats.totalBytes += contentLength;
        saveStatsDB();

        userActivity.set(userInfo.username, "✅ อัปโหลดสำเร็จ!");
        
        if (wsMap.has(userInfo.uuid)) {
            const buffer = Buffer.allocUnsafe(17); buffer.writeUInt8(2, 0); 
            userInfo.hexUuidBuffer.copy(buffer, 1); 
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
            const buffer = Buffer.allocUnsafe(17); buffer.writeUInt8(2, 0); 
            userInfo.hexUuidBuffer.copy(buffer, 1); 
            wsMap.get(userInfo.uuid).forEach(ws => safeSend(ws, buffer));
        }
        res.send("success");
    } catch (err) { res.status(404).end(); }
});

app.get('/api/:uuid/avatar', async (req, res) => { 
    const uuidStr = req.params.uuid;
    // ✅ [สมบูรณ์] เพิ่ม stats-secret และตัวอื่นๆ ไม่ให้ Mod บั๊กตอนหาข้อมูล
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
    // ✅ [สมบูรณ์] เพิ่ม stats-secret เช่นกัน
    if (["motd", "version", "auth", "limits", "stats-secret"].includes(uuidStr)) return res.status(404).end();
    const uuid = formatUuid(uuidStr);
    if (!uuid) return res.status(404).end();

    const data = { uuid: uuid, rank: "normal", equipped: [], lastUsed: new Date().toISOString(), equippedBadges: { special: Array(15).fill(0), pride: Array(30).fill(0) }, version: "0.1.5", banned: false };
    let fileHash = hashCache.get(uuid);
    const avatarFile = path.join(__dirname, 'avatars', `${uuid}.moon`);
    
    if (!fileHash) {
        try {
            await fsp.access(avatarFile);
            const hashStream = crypto.createHash('sha256');
            const readStream = fs.createReadStream(avatarFile);
            await pipeline(readStream, hashStream);
            fileHash = hashStream.digest('hex');
            hashCache.set(uuid, fileHash);
            saveCache();
        } catch (e) {}
    }
    if (fileHash) data.equipped.push({ id: 'avatar', owner: uuid, hash: fileHash });
    res.json(data);
});

app.get('/', (req, res) => { res.status(200).send(MOTD_MESSAGE); });

// ==========================================
// ⚡ WEBSOCKET 
// ==========================================
const server = http.createServer(app);
server.keepAliveTimeout = 60000; 
server.headersTimeout = 65000;

const wss = new WebSocket.Server({ 
    server, 
    perMessageDeflate: false,
    maxPayload: LIMIT_BYTES + 1048576 
});

wss.on('connection', (ws) => {
    ws.isAlive = true; 
    ws.on('pong', () => { ws.isAlive = true; }); 

    ws.on('message', (data) => {
        try {
            if (!Buffer.isBuffer(data) || data.length < 1) return; 

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
                userInfo.hexUuidBuffer.copy(newbuffer, 1); 
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
        } catch (e) {} 
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
}, WS_PING_INTERVAL_MS); 

wss.on('close', () => clearInterval(interval));

server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n${c.p}==========================================${c.rst}`);
    console.log(`${c.b}✨ BIGAVATAR CLOUD - V10 (ANTI-DROP EDITION)${c.rst}`);
    console.log(`${c.g}✅ API Link: ${API_URL}${c.rst}`);
    console.log(`${c.y}⚡ Stability Ping & Sync Adjusted (No Disconnects)${c.rst}`);
    console.log(`${c.y}⚡ Maintenance Mode Support Active${c.rst}`);
    console.log(`${c.y}🎨 Custom MOTD Active${c.rst}`);
    console.log(`${c.p}==========================================${c.rst}\n`);
    sendToDiscord("✅ **[อัปเดตระบบ]** เซิร์ฟเวอร์ Figura ออนไลน์ (แก้ไขปัญหาเน็ตหลุด & โหมดปิดปรับปรุง & อัปเกรด MOTD)!");
});
