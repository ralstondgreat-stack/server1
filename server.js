'use strict';
// ParentGuard relay API. Deploy behind a managed HTTPS reverse proxy (TLS required).
// Relay state is persisted to DATA_DIR when a persistent disk is configured. Screen frames remain transient.
const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const PORT = Number(process.env.PORT || 8080);
const devices = new Map();
const pairCodes = new Map();
const parentTokens = new Map();
const claimAttempts = new Map();
// Configure DATA_DIR to a mounted persistent disk (for Render, commonly /var/data).
// The default local ./data directory is NOT persistent on ephemeral hosting.
const DATA_DIR = process.env.DATA_DIR || process.env.PG_DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'parentguard-state.json');
let persistTimer = null;
function loadState() {
  try {
    if (!fs.existsSync(DATA_FILE)) return;
    const saved = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    for (const d of (saved.devices || [])) {
      // Screen frames are transient and deliberately not restored after restart.
      d.frame = null;
      devices.set(d.id, d);
    }
    for (const [k, v] of (saved.pairCodes || [])) pairCodes.set(k, v);
    for (const [k, v] of (saved.parentTokens || [])) parentTokens.set(k, v);
    console.log('Restored persistent state: ' + devices.size + ' devices, ' + parentTokens.size + ' parent tokens');
  } catch (e) {
    console.error('Could not load persistent state:', e.message);
  }
}
function persistState() {
  if (persistTimer) clearTimeout(persistTimer);
  persistTimer = setTimeout(() => {
    persistTimer = null;
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      const state = {
        savedAt: now(),
        devices: Array.from(devices.values()).map(d => ({ ...d, frame: null })),
        pairCodes: Array.from(pairCodes.entries()),
        parentTokens: Array.from(parentTokens.entries())
      };
      const temp = DATA_FILE + '.tmp';
      fs.writeFileSync(temp, JSON.stringify(state), { mode: 0o600 });
      fs.renameSync(temp, DATA_FILE);
    } catch (e) { console.error('Persistent state save failed:', e.message); }
  }, 100);
  if (persistTimer.unref) persistTimer.unref();
}
loadState();
const MAX_BODY = 2 * 1024 * 1024;
const now = () => Date.now();
const token = () => crypto.randomBytes(32).toString('base64url');
const code = () => String(crypto.randomInt(100000, 1000000));
function send(res, status, obj) { const b = Buffer.from(JSON.stringify(obj)); res.writeHead(status, {'content-type':'application/json; charset=utf-8','content-length':b.length,'cache-control':'no-store','x-content-type-options':'nosniff'}); res.end(b); }
function read(req) { return new Promise((resolve,reject)=>{ let chunks=[], size=0; req.on('data',c=>{size+=c.length;if(size>MAX_BODY){reject(new Error('body too large'));req.destroy();}else chunks.push(c);}); req.on('end',()=>{try{resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')||'{}'));}catch(e){reject(e);}}); req.on('error',reject); }); }
function bearer(req) { const h=req.headers.authorization||''; return h.startsWith('Bearer ')?h.slice(7):''; }
function getDevice(req) { const t=bearer(req); for(const d of devices.values()) if(d.token===t) return d; return null; }
function getParent(req) { const t=bearer(req); return parentTokens.get(t)||null; }
function clean() { for(const [c,v] of pairCodes) if(v.expires<now()) pairCodes.delete(c); for(const [t,v] of parentTokens) if(v.expires<now()) parentTokens.delete(t); for(const d of devices.values()) if(d.request && d.request.expires<now()) d.request=null; }
const server=http.createServer(async(req,res)=>{
  res.setHeader('access-control-allow-origin','*'); res.setHeader('access-control-allow-headers','content-type,authorization'); res.setHeader('access-control-allow-methods','GET,POST,OPTIONS');
  if(req.method==='OPTIONS'){res.writeHead(204);return res.end();}
  try {
    clean(); const u=new URL(req.url,'http://localhost');
    if(req.method==='GET'&&u.pathname==='/health') return send(res,200,{ok:true,service:'ParentGuard relay',version:'3.3.0',websocket:'/v1/ws'});
    if(req.method==='POST'&&u.pathname==='/v1/pair/start'){
      const b=await read(req); const deviceId=crypto.randomUUID(); const deviceToken=token(); const pairingCode=code();
      devices.set(deviceId,{id:deviceId,token:deviceToken,created:now(),lastSeen:0,snapshot:{status:'Waiting for first sync'},frame:null,request:null,sharing:false,messages:[],emergencyAlerts:[],emergencyDelivered:[],control:null});
      persistState();
      pairCodes.set(pairingCode,{deviceId,expires:now()+5*60*1000});
      persistState();
      return send(res,200,{deviceId,deviceToken,pairingCode,expiresInSeconds:300});
    }
    if(req.method==='POST'&&u.pathname==='/v1/pair/claim'){
      const ip=String(req.headers['x-forwarded-for']||req.socket.remoteAddress||'unknown').split(',')[0].trim();
      const attempts=claimAttempts.get(ip)||{count:0,start:now()}; if(now()-attempts.start>5*60*1000){attempts.count=0;attempts.start=now();} attempts.count++; claimAttempts.set(ip,attempts);
      if(attempts.count>12)return send(res,429,{error:'Too many pairing attempts. Wait five minutes.'});
      const b=await read(req); const p=pairCodes.get(String(b.code||'')); if(!p||p.expires<now()) return send(res,401,{error:'Pairing code invalid or expired'});
      pairCodes.delete(String(b.code)); const parentToken=token(); parentTokens.set(parentToken,{deviceId:p.deviceId,expires:now()+30*24*60*60*1000}); persistState();
      return send(res,200,{deviceId:p.deviceId,parentToken,expiresInSeconds:30*24*60*60});
    }
    if(req.method==='POST'&&u.pathname==='/v1/snapshot'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); const b=await read(req);
      d.snapshot={...b,receivedAt:now()}; d.lastSeen=now(); persistState(); return send(res,200,{ok:true,request:d.request?{id:d.request.id,expires:d.request.expires}:null});
    }
    if(req.method==='GET'&&u.pathname==='/v1/snapshot'){
      const p=getParent(req); if(!p)return send(res,401,{error:'Invalid parent token'}); const d=devices.get(p.deviceId); if(!d)return send(res,404,{error:'Device not found'});
      return send(res,200,{deviceId:d.id,online:now()-d.lastSeen<60000,lastSeen:d.lastSeen,snapshot:d.snapshot,sharing:d.sharing,request:d.request?{id:d.request.id,expires:d.request.expires}:null});
    }
    if(req.method==='POST'&&u.pathname==='/v1/control'){
      const p=getParent(req); if(!p)return send(res,401,{error:'Invalid parent token'}); const d=devices.get(p.deviceId); if(!d)return send(res,404,{error:'Device not found'});
      const b=await read(req); const action=String(b.action||''); if(!['lock','unlock','set_limit'].includes(action))return send(res,400,{error:'Unsupported control action'});
      d.control={id:token(),action,minutes:Math.max(0,Math.min(720,Number(b.minutes)||0)),created:now()}; persistState(); notifyDevice(d.id,'control',d.control); return send(res,200,{ok:true,action:d.control.action});
    }
    if(req.method==='GET'&&u.pathname==='/v1/control'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); const control=d.control||null; d.control=null; persistState(); return send(res,200,{control});
    }
    // Parent-to-child urgent emergency alert queue. Alerts remain queued until child ACKs.
    if(req.method==='POST'&&u.pathname==='/v1/emergency/alert'){
      const p=getParent(req); if(!p)return send(res,401,{error:'Invalid parent token'}); const d=devices.get(p.deviceId); if(!d)return send(res,404,{error:'Device not found'});
      const b=await read(req); const message=String(b.message||'Please check in with your parent now.').trim();
      if(!message)return send(res,400,{error:'Emergency message cannot be empty'});
      if(message.length>500)return send(res,413,{error:'Emergency message must be 500 characters or fewer'});
      const queue=d.emergencyAlerts||(d.emergencyAlerts=[]); if(queue.length>=100)return send(res,429,{error:'Emergency queue is full; clear pending alerts before sending another.'});
      const item={id:token(),text:message,created:now(),kind:'emergency',status:'queued'}; queue.push(item);
      persistState(); notifyDevice(d.id,'emergency_alert',item); return send(res,200,{ok:true,alertId:item.id,queued:true,status:'queued'});
    }
    if(req.method==='GET'&&u.pathname==='/v1/emergency/inbox'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); return send(res,200,{alert:(d.emergencyAlerts||[])[0]||null});
    }
    if(req.method==='POST'&&u.pathname==='/v1/emergency/ack'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); const b=await read(req); const id=String(b.id||''); const index=(d.emergencyAlerts||[]).findIndex(x=>x.id===id); if(index>=0){const item=d.emergencyAlerts.splice(index,1)[0]; item.status='notification_posted'; item.deliveredAt=now(); d.emergencyDelivered=d.emergencyDelivered||[]; d.emergencyDelivered.push(item); if(d.emergencyDelivered.length>100)d.emergencyDelivered=d.emergencyDelivered.slice(-100); persistState();} return send(res,200,{ok:true,recorded:index>=0});
    }
    if(req.method==='GET'&&u.pathname==='/v1/emergency/status'){
      const p=getParent(req); if(!p)return send(res,401,{error:'Invalid parent token'}); const d=devices.get(p.deviceId); if(!d)return send(res,404,{error:'Device not found'});
      const latest=(d.emergencyAlerts||[]).slice(-1)[0]||null; const delivered=(d.emergencyDelivered||[]).slice(-1)[0]||null; return send(res,200,{queued:(d.emergencyAlerts||[]).length,latest:latest?{id:latest.id,created:latest.created,text:latest.text,status:latest.status||'queued'}:null,lastDelivered:delivered?{id:delivered.id,created:delivered.created,deliveredAt:delivered.deliveredAt,text:delivered.text,status:delivered.status}:null,online:now()-d.lastSeen<60000,lastSeen:d.lastSeen});
    }
    if(req.method==='POST'&&u.pathname==='/v1/message'){
      const p=getParent(req); if(!p)return send(res,401,{error:'Invalid parent token'}); const d=devices.get(p.deviceId); if(!d)return send(res,404,{error:'Device not found'});
      const b=await read(req); const message=String(b.message||'').trim(); if(!message)return send(res,400,{error:'Message cannot be empty'}); if(message.length>500)return send(res,413,{error:'Message must be 500 characters or fewer'});
      const item={id:token(),text:message,created:now()}; d.messages=d.messages||[]; d.messages.push(item); if(d.messages.length>20)d.messages=d.messages.slice(-20);
      persistState(); notifyDevice(d.id,'message',item); return send(res,200,{ok:true,messageId:item.id});
    }
    if(req.method==='GET'&&u.pathname==='/v1/message'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); const item=(d.messages||[])[0]||null; return send(res,200,{message:item});
    }
    if(req.method==='POST'&&u.pathname==='/v1/message/ack'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); const b=await read(req); d.messages=(d.messages||[]).filter(m=>m.id!==String(b.id||'')); persistState(); return send(res,200,{ok:true});
    }
    // SMS history is shared only after explicit opt-in and Android SMS permission on the child device.
    if(req.method==='POST'&&u.pathname==='/v1/sms/sync'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'});
      const b=await read(req); const incoming=Array.isArray(b.messages)?b.messages:[];
      if(incoming.length>100)return send(res,413,{error:'Maximum 100 SMS records per batch'});
      d.smsHistory=d.smsHistory||[]; const known=new Set(d.smsHistory.map(x=>String(x.sourceId)));
      for(const m of incoming){
        if(!m||m.sourceId==null)continue;
        const sourceId=String(m.sourceId); if(!/^\d{1,20}$/.test(sourceId)||known.has(sourceId))continue;
        const body=String(m.body||''); const address=String(m.address||'Unknown sender');
        if(body.length>10000||address.length>300)continue;
        d.smsHistory.push({sourceId,address,body,date:Math.max(0,Number(m.date)||0),direction:['incoming','outgoing'].includes(m.direction)?m.direction:'other',receivedAt:now()}); known.add(sourceId);
      }
      d.smsHistory.sort((a,b)=>a.date-b.date); if(d.smsHistory.length>2000)d.smsHistory=d.smsHistory.slice(-2000);
      d.smsHistoryUpdatedAt=now(); persistState(); return send(res,200,{ok:true,accepted:incoming.length,total:d.smsHistory.length,updatedAt:d.smsHistoryUpdatedAt});
    }
    if(req.method==='GET'&&u.pathname==='/v1/sms/history'){
      const p=getParent(req); if(!p)return send(res,401,{error:'Invalid parent token'}); const d=devices.get(p.deviceId); if(!d)return send(res,404,{error:'Device not found'});
      const q=String(u.searchParams.get('q')||'').toLowerCase().slice(0,100); const all=d.smsHistory||[];
      const filtered=q?all.filter(m=>String(m.address||'').toLowerCase().includes(q)||String(m.body||'').toLowerCase().includes(q)):all;
      return send(res,200,{messages:filtered.slice(-1000).reverse(),total:all.length,updatedAt:d.smsHistoryUpdatedAt||0,enabled:!!d.smsHistory});
    }
    // Remote app blocking: each parent token is scoped to its paired child device.
    if(req.method==='POST'&&u.pathname==='/v1/apps/catalog'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); const b=await read(req); const incoming=Array.isArray(b.apps)?b.apps:[]; d.appCatalog=[];
      for(const a of incoming.slice(0,300)){if(!a)continue;const packageName=String(a.packageName||'');const label=String(a.label||packageName);if(!/^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$/.test(packageName)||label.length>200)continue;d.appCatalog.push({packageName,label});}
      d.appCatalogUpdatedAt=now(); d.lastSeen=now(); persistState(); return send(res,200,{ok:true,count:d.appCatalog.length,updatedAt:d.appCatalogUpdatedAt});
    }
    if(req.method==='GET'&&u.pathname==='/v1/apps/catalog'){
      const p=getParent(req); if(!p)return send(res,401,{error:'Invalid parent token'}); const d=devices.get(p.deviceId); if(!d)return send(res,404,{error:'Device not found'});
      return send(res,200,{apps:d.appCatalog||[],blocked:Object.keys(d.appBlocks||{}).filter(k=>d.appBlocks[k]===true),statuses:d.appBlockStatus||{},updatedAt:d.appCatalogUpdatedAt||0,online:now()-d.lastSeen<60000});
    }
    if(req.method==='POST'&&u.pathname==='/v1/apps/block'){
      const p=getParent(req); if(!p)return send(res,401,{error:'Invalid parent token'}); const d=devices.get(p.deviceId); if(!d)return send(res,404,{error:'Device not found'}); const b=await read(req); const pkg=String(b.packageName||''); if(!/^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$/.test(pkg))return send(res,400,{error:'Invalid package name'});
      if(!(d.appCatalog||[]).some(a=>a.packageName===pkg))return send(res,400,{error:'App is not present in the latest child app catalog'});
      d.appBlocks=d.appBlocks||{}; if(b.blocked===true)d.appBlocks[pkg]=true;else delete d.appBlocks[pkg]; d.appBlockCommandAt=now(); d.appBlockStatus=d.appBlockStatus||{}; d.appBlockStatus[pkg]={desired:!!b.blocked,status:'pending',updatedAt:now()}; persistState(); notifyDevice(d.id,'app_blocks_updated',{packageName:pkg,blocked:!!b.blocked}); return send(res,200,{ok:true,status:'Command queued; waiting for child sync'});
    }
    if(req.method==='GET'&&u.pathname==='/v1/apps/blocks'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); return send(res,200,{blocked:Object.keys(d.appBlocks||{}).filter(k=>d.appBlocks[k]===true),updatedAt:d.appBlockCommandAt||0});
    }
    if(req.method==='POST'&&u.pathname==='/v1/apps/blocks/status'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); const b=await read(req); const pkg=String(b.packageName||''); if(!/^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$/.test(pkg))return send(res,400,{error:'Invalid package name'}); d.appBlockStatus=d.appBlockStatus||{}; d.appBlockStatus[pkg]={desired:!!b.blocked,status:'synced',updatedAt:now()}; persistState(); return send(res,200,{ok:true});
    }
    if(req.method==='POST'&&u.pathname==='/v1/screen/request'){
      const p=getParent(req); if(!p)return send(res,401,{error:'Invalid parent token'}); const d=devices.get(p.deviceId); if(!d)return send(res,404,{error:'Device not found'});
      d.request={id:token(),created:now(),expires:now()+2*60*1000}; persistState(); notifyDevice(d.id,'screen_request',{id:d.request.id,expires:d.request.expires}); return send(res,200,{ok:true,expiresInSeconds:120});
    }
    if(req.method==='GET'&&u.pathname==='/v1/screen/request'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); return send(res,200,{request:d.request?{id:d.request.id,expires:d.request.expires}:null});
    }
    if(req.method==='POST'&&u.pathname==='/v1/screen/state'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); const b=await read(req); d.sharing=!!b.sharing; if(!d.sharing)d.frame=null; if(b.requestId&&d.request&&d.request.id===b.requestId)d.request=null; persistState(); return send(res,200,{ok:true});
    }
    if(req.method==='POST'&&u.pathname==='/v1/screen/frame'){
      const d=getDevice(req); if(!d)return send(res,401,{error:'Invalid device token'}); const b=await read(req); if(!d.sharing)return send(res,403,{error:'No approved screen session'});
      const raw=String(b.jpegBase64||''); if(raw.length>1500000)return send(res,413,{error:'Frame too large'}); if(!/^[A-Za-z0-9+/]*={0,2}$/.test(raw))return send(res,400,{error:'Invalid frame'});
      d.frame={jpegBase64:raw,at:now()}; d.lastSeen=now(); return send(res,200,{ok:true});
    }
    if(req.method==='GET'&&u.pathname==='/v1/screen/status'){
      const p=getParent(req); if(!p)return send(res,401,{error:'Invalid parent token'}); const d=devices.get(p.deviceId); if(!d)return send(res,404,{error:'Device not found'});
      const pending=!!(d.request&&d.request.expires>now());
      const state=d.sharing?'sharing':(pending?'awaiting_child_approval':'not_active');
      return send(res,200,{state,online:now()-d.lastSeen<60000,requestExpires:d.request?d.request.expires:0,frameAt:d.frame?d.frame.at:0});
    }
    if(req.method==='GET'&&u.pathname==='/v1/screen/frame'){
      const p=getParent(req); if(!p)return send(res,401,{error:'Invalid parent token'}); const d=devices.get(p.deviceId); if(!d)return send(res,404,{error:'Device not found'}); return send(res,200,{sharing:d.sharing,frame:d.frame});
    }
    return send(res,404,{error:'Not found'});
  } catch(e) { return send(res,400,{error:'Bad request'}); }
});
// WSS runs on the same HTTPS origin/port. The hosting platform terminates TLS.
const wss = new WebSocket.Server({ noServer: true, maxPayload: 64 * 1024 });
const sockets = new Map(); // deviceId -> { parent:Set, child:ws }
// Keep idle sockets from silently hanging behind mobile networks and hosting proxies.
const heartbeat = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws._pgAlive === false) { ws.terminate(); continue; }
    ws._pgAlive = false;
    try { ws.ping(); } catch (_) { ws.terminate(); }
  }
}, 30000);
if (heartbeat.unref) heartbeat.unref();
function sendWs(ws, type, data) { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({type, data: data || {}, at: now()})); }
function notifyDevice(deviceId, type, data) {
  const group=sockets.get(deviceId); if(!group)return;
  if(group.child)sendWs(group.child,type,data);
  if(group.parent)for(const ws of group.parent)sendWs(ws,type,data);
}
server.on('upgrade',(req,socket,head)=>{
  let u; try{u=new URL(req.url,'http://localhost');}catch(e){socket.destroy();return;}
  if(u.pathname!=='/v1/ws'){socket.destroy();return;}
  wss.handleUpgrade(req,socket,head,ws=>wss.emit('connection',ws,req));
});
wss.on('connection',(ws)=>{
  ws._pgAlive = true;
  ws.on('pong',()=>{ ws._pgAlive = true; });
  let authenticated=false, role='', deviceId='';
  const authTimer=setTimeout(()=>{if(!authenticated)ws.close(1008,'authentication required');},8000);
  ws.on('message',(raw)=>{
    let msg; try{msg=JSON.parse(String(raw));}catch(e){ws.close(1007,'invalid JSON');return;}
    if(!authenticated){
      if(msg.type!=='auth'||!msg.token||!['parent','child'].includes(msg.role)){ws.close(1008,'invalid authentication');return;}
      let d=null, p=null;
      if(msg.role==='child'){for(const x of devices.values())if(x.token===msg.token){d=x;break;} if(d){role='child';deviceId=d.id;}}
      else {p=parentTokens.get(msg.token);if(p&&p.expires>now()){role='parent';deviceId=p.deviceId;}}
      if(!deviceId){ws.close(1008,'invalid token');return;}
      authenticated=true;clearTimeout(authTimer);
      let group=sockets.get(deviceId);if(!group){group={parent:new Set(),child:null};sockets.set(deviceId,group);}
      if(role==='child')group.child=ws;else group.parent.add(ws);
      ws._pg={role,deviceId}; sendWs(ws,'ready',{role,deviceId});
      notifyDevice(deviceId,'connection',{role,connected:true}); return;
    }
    // Application messages are intentionally not accepted from clients yet; all actions
    // still pass through validated HTTPS endpoints. WSS is an authenticated event channel.
    if(msg.type==='ping')sendWs(ws,'pong',{});
  });
  ws.on('close',()=>{clearTimeout(authTimer);if(!ws._pg)return;const g=sockets.get(ws._pg.deviceId);if(g){if(ws._pg.role==='child'&&g.child===ws)g.child=null;if(ws._pg.role==='parent')g.parent.delete(ws);if(!g.child&&g.parent.size===0)sockets.delete(ws._pg.deviceId);}notifyDevice(ws._pg.deviceId,'connection',{role:ws._pg.role,connected:false});});
  ws.on('error',()=>{});
});
// Publish events after the existing HTTPS route has validated its bearer token and payload.
const originalSend=send;
server.listen(PORT,'0.0.0.0',()=>console.log('ParentGuard relay v3.2.0 listening on '+PORT+'; HTTPS API + authenticated WSS /v1/ws'));
process.on('SIGTERM',()=>{ clearInterval(heartbeat); if(persistTimer){clearTimeout(persistTimer);persistTimer=null;} try { fs.mkdirSync(DATA_DIR,{recursive:true}); const state={savedAt:now(),devices:Array.from(devices.values()).map(d=>({...d,frame:null})),pairCodes:Array.from(pairCodes.entries()),parentTokens:Array.from(parentTokens.entries())}; const temp=DATA_FILE+'.tmp'; fs.writeFileSync(temp,JSON.stringify(state),{mode:0o600}); fs.renameSync(temp,DATA_FILE); } catch(e){console.error('Final state save failed:',e.message);}  for(const ws of wss.clients) ws.close(1001,'server shutting down'); server.close(()=>process.exit(0)); setTimeout(()=>process.exit(0),5000).unref(); });
