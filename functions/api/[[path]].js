const ITERATIONS = 100000;
const DAYS = 7;
const enc = new TextEncoder();
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
const un64 = s => Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
const hash = async s => b64(await crypto.subtle.digest("SHA-256",enc.encode(s)));
const token = () => { const b=new Uint8Array(32); crypto.getRandomValues(b); return b64(b); };
const response = (data,status=200,headers={}) => new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store",...headers}});
const error = (message,status=400) => response({ok:false,error:message},status);
const emailOK = s => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) && s.length<=254;
const passOK = s => typeof s==="string" && s.length>=12 && s.length<=128;
async function passwordHash(password) {
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const key=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:ITERATIONS,hash:"SHA-256"},key,256);
  return {salt:b64(salt),hash:b64(bits),iterations:ITERATIONS};
}
async function passwordOK(password,user) {
  const key=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2",salt:un64(user.password_salt),iterations:user.password_iterations,hash:"SHA-256"},key,256));
  const expected=un64(user.password_hash);
  return bits.length===expected.length && bits.every((v,i)=>v===expected[i]);
}
function cookie(token,maxAge) { return `hrh_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`; }
function readCookie(req) { const v=(req.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith("hrh_session=")); return v?v.slice(12):""; }
function originOK(req) { const o=req.headers.get("Origin"); return !o || o===new URL(req.url).origin; }
async function input(req) { try{return await req.json()}catch{return null} }
async function current(req,env) {
  const t=readCookie(req); if(!t)return null;
  return await env.DB.prepare("SELECT u.id,u.name,u.email,u.role,u.status,u.must_change_password FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.status='approved'")
    .bind(await hash(t),Date.now()).first();
}
const safeUser=u=>({id:u.id,name:u.name,email:u.email,role:u.role,mustChangePassword:!!u.must_change_password});
async function session(req,env,u) {
  const t=token(),now=Date.now();
  await env.DB.prepare("INSERT INTO sessions(id,user_id,token_hash,created_at,expires_at) VALUES(?,?,?,?,?)").bind(crypto.randomUUID(),u.id,await hash(t),now,now+DAYS*86400000).run();
  return response({ok:true,user:safeUser(u)},200,{"set-cookie":cookie(t,DAYS*86400)});
}
async function auth(req,env,admin=false,allowMustChange=false) {
  const u=await current(req,env);
  if(!u)return {res:error("Please sign in again.",401)};
  if(admin && u.role!=="admin")return {res:error("Team Lead access required.",403)};
  if(!allowMustChange && u.must_change_password)return {res:error("Change your temporary password to continue.",403)};
  return {u};
}
async function route(req,env) {
  const url=new URL(req.url),p=url.pathname;
  if(p.startsWith("/api/") && req.method!=="GET" && !originOK(req))return error("Cross-origin request blocked.",403);
  if(p==="/api/health" && req.method==="GET")return response({ok:true,service:"IndiFrame Agent Help Desk API"});
  if(p==="/api/setup/admin" && req.method==="POST") {
    const configuredSetupToken=String(env.ADMIN_SETUP_TOKEN||"").trim();
    if(!configuredSetupToken)return error("Admin setup is not configured.",503);
    const d=await input(req);
    const submittedSetupToken=typeof d?.setupToken==="string"?d.setupToken.trim():"";
    if(!submittedSetupToken || submittedSetupToken!==configuredSetupToken)return error("Invalid setup token.",403);
    if(await env.DB.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").first())return error("Team Lead account already initialized.",409);
    const name=String(d.name||"").trim(),email=String(d.email||"").trim().toLowerCase();
    if(!name||name.length>100||!emailOK(email)||!passOK(d.password))return error("Enter name, valid work email and a unique password of at least 12 characters.");
    const h=await passwordHash(d.password),id=crypto.randomUUID(),now=Date.now();
    await env.DB.prepare("INSERT INTO users(id,name,email,role,status,password_hash,password_salt,password_iterations,must_change_password,created_at,updated_at) VALUES(?,?,?,'admin','approved',?,?,?,0,?,?)").bind(id,name,email,h.hash,h.salt,h.iterations,now,now).run();
    return session(req,env,{id,name,email,role:"admin",must_change_password:0});
  }
  if(p==="/api/auth/login" && req.method==="POST") {
    const d=await input(req),email=String(d?.email||"").trim().toLowerCase();
    if(!emailOK(email)||typeof d.password!=="string")return error("Invalid email or password.",401);
    const ip=req.headers.get("CF-Connecting-IP")||"unknown",key=await hash(email+"|"+ip),cut=Date.now()-900000;
    await env.DB.prepare("DELETE FROM login_attempts WHERE attempted_at<?").bind(cut).run();
    const attempts=await env.DB.prepare("SELECT COUNT(*) n FROM login_attempts WHERE attempt_key=? AND attempted_at>?").bind(key,cut).first();
    if((attempts?.n||0)>=8)return error("Too many attempts. Try again after 15 minutes.",429);
    const u=await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
    if(!u||u.status!=="approved"||!u.password_hash||!(await passwordOK(d.password,u))) {
      await env.DB.prepare("INSERT INTO login_attempts(attempt_key,attempted_at) VALUES(?,?)").bind(key,Date.now()).run();
      return error("Invalid credentials or account is not approved.",401);
    }
    await env.DB.prepare("DELETE FROM login_attempts WHERE attempt_key=?").bind(key).run();
    await env.DB.prepare("UPDATE users SET last_login_at=?,updated_at=? WHERE id=?").bind(Date.now(),Date.now(),u.id).run();
    return session(req,env,u);
  }
  if(p==="/api/auth/me" && req.method==="GET") {
    const u=await current(req,env);return u?response({ok:true,user:safeUser(u)}):error("Not signed in.",401);
  }
  if(p==="/api/auth/change-password" && req.method==="POST") {
    const a=await auth(req,env,false,true);if(a.res)return a.res;
    const d=await input(req),u=await env.DB.prepare("SELECT * FROM users WHERE id=?").bind(a.u.id).first();
    if(!d||typeof d.currentPassword!=="string"||!passOK(d.newPassword))return error("New password must be at least 12 characters.");
    if(!await passwordOK(d.currentPassword,u))return error("Current password is incorrect.",401);
    const h=await passwordHash(d.newPassword);
    await env.DB.prepare("UPDATE users SET password_hash=?,password_salt=?,password_iterations=?,must_change_password=0,updated_at=? WHERE id=?").bind(h.hash,h.salt,h.iterations,Date.now(),u.id).run();
    return response({ok:true,message:"Password updated."});
  }
  if(p==="/api/auth/logout" && req.method==="POST") {
    const t=readCookie(req);if(t)await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await hash(t)).run();
    return response({ok:true},200,{"set-cookie":"hrh_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"});
  }
  if(p==="/api/admin/agents" && req.method==="GET") {
    const a=await auth(req,env,true);if(a.res)return a.res;
    const rows=await env.DB.prepare("SELECT id,name,email,status,must_change_password,created_at,last_login_at FROM users WHERE role='agent' ORDER BY created_at DESC").all();
    return response({ok:true,agents:rows.results||[]});
  }
  if(p==="/api/admin/agents" && req.method==="POST") {
    const a=await auth(req,env,true);if(a.res)return a.res;
    const d=await input(req),name=String(d?.name||"").trim(),email=String(d?.email||"").trim().toLowerCase();
    if(!name||name.length>100||!emailOK(email))return error("Enter agent name and valid work email.");
    if(await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first())return error("Email already exists.",409);
    const id=crypto.randomUUID(),now=Date.now();
    await env.DB.prepare("INSERT INTO users(id,name,email,role,status,must_change_password,created_at,updated_at) VALUES(?,?,?,'agent','pending',1,?,?)").bind(id,name,email,now,now).run();
    return response({ok:true,agentId:id,message:"Agent added as pending. Approve to activate access."},201);
  }
  const m=p.match(/^\/api\/admin\/agents\/([a-f0-9-]+)$/i);
  if(m&&req.method==="PATCH") {
    const a=await auth(req,env,true);if(a.res)return a.res;
    const d=await input(req),id=m[1];
    if(!["approved","pending","disabled"].includes(d?.status))return error("Invalid status.");
    const u=await env.DB.prepare("SELECT id,role,status FROM users WHERE id=?").bind(id).first();
    if(!u||u.role!=="agent")return error("Agent not found.",404);
    if(d.status==="approved"&&u.status!=="approved") {
      if(!env.AGENT_INITIAL_PASSWORD)return error("Agent temporary password secret is not configured.",503);
      const h=await passwordHash(env.AGENT_INITIAL_PASSWORD);
      await env.DB.prepare("UPDATE users SET status='approved',password_hash=?,password_salt=?,password_iterations=?,must_change_password=1,updated_at=? WHERE id=?").bind(h.hash,h.salt,h.iterations,Date.now(),id).run();
    } else await env.DB.prepare("UPDATE users SET status=?,updated_at=? WHERE id=?").bind(d.status,Date.now(),id).run();
    if(d.status!=="approved")await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(id).run();
    return response({ok:true,message:"Agent status updated."});
  }
  if(p==="/api/admin/agents/reset-password"&&req.method==="POST") {
    const a=await auth(req,env,true);if(a.res)return a.res;
    const d=await input(req),u=await env.DB.prepare("SELECT id,role,status FROM users WHERE id=?").bind(String(d?.agentId||"")).first();
    if(!u||u.role!=="agent")return error("Agent not found.",404);
    if(u.status!=="approved")return error("Only approved agents can be reset.",409);
    if(!env.AGENT_INITIAL_PASSWORD)return error("Agent temporary password secret is not configured.",503);
    const h=await passwordHash(env.AGENT_INITIAL_PASSWORD);
    await env.DB.prepare("UPDATE users SET password_hash=?,password_salt=?,password_iterations=?,must_change_password=1,updated_at=? WHERE id=?").bind(h.hash,h.salt,h.iterations,Date.now(),u.id).run();
    await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(u.id).run();
    return response({ok:true,message:"Temporary password reset; agent must change it at next login."});
  }
  return error("Not found.",404);
}
export async function onRequest({request,env}) {
  try {
    return await route(request,env);
  } catch (e) {
    console.error("IndiFrame API request failed", {
      path: new URL(request.url).pathname,
      method: request.method,
      errorName: e?.name || "Error",
      errorMessage: String(e?.message || e).slice(0,500)
    });
    return error("Internal server error.",500);
  }
}
