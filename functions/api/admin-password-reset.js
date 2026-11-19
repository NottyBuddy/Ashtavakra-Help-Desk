const enc = new TextEncoder();
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
const hash = async s => b64(await crypto.subtle.digest("SHA-256",enc.encode(s)));
const response = (data,status=200) => new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store"}});
const fail = (message,status=400) => response({ok:false,error:message},status);
const emailOK = s => typeof s==="string" && /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(s) && s.length<=254;
const passOK = s => typeof s==="string" && s.length>=12 && s.length<=128;
const randomSalt = () => {const b=new Uint8Array(16);crypto.getRandomValues(b);return b64(b);};
const randomOtp = () => String(crypto.getRandomValues(new Uint32Array(1))[0]%1000000).padStart(6,"0");
async function passwordHash(password){
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const key=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:100000,hash:"SHA-256"},key,256);
  return {salt:b64(salt),hash:b64(bits),iterations:100000};
}
async function ensureTable(env){
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS admin_password_otps (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, otp_salt TEXT NOT NULL, otp_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL)").run();
}
async function sendOtp(env,email,otp){
  const payload={
    from:env.RESEND_FROM_EMAIL,
    to:[email],
    subject:"IndiFrame Team Lead password reset code",
    html:`<div style="font-family:Arial,sans-serif;color:#172236;max-width:520px;margin:auto;padding:24px"><div style="font-size:12px;letter-spacing:2px;color:#bd7048;font-weight:bold">INDIFRAME · HRHNEXT</div><h2 style="color:#258fbe">Password reset verification</h2><p>Your Team Lead password reset code is:</p><div style="font-size:32px;letter-spacing:8px;font-weight:bold;padding:18px;background:#f5f7fa;border-radius:10px;text-align:center">${otp}</div><p>This code expires in 10 minutes and can be used only once.</p><p>If you did not request this reset, ignore this email. Do not share this code with anyone.</p></div>`
  };
  const r=await fetch("https://api.resend.com/emails",{method:"POST",headers:{"authorization":"Bearer "+env.RESEND_API_KEY,"content-type":"application/json"},body:JSON.stringify(payload)});
  if(!r.ok){const detail=await r.text().catch(()=>"");console.error("Resend delivery failed",r.status,detail.slice(0,300));throw new Error("Email delivery failed.");}
}
export async function onRequestPost({request,env}){
  try{
    const origin=request.headers.get("Origin");
    if(origin && origin!==new URL(request.url).origin)return fail("Cross-origin request blocked.",403);
    if(!env.RESEND_API_KEY || !env.RESEND_FROM_EMAIL)return fail("Email OTP service is not configured yet. Contact the deployment administrator.",503);
    await ensureTable(env);
    const d=await request.json().catch(()=>null);
    const action=d?.action;
    const email=String(d?.email||"").trim().toLowerCase();
    if(!emailOK(email))return fail("Enter your registered Team Lead work email.");
    const ip=request.headers.get("CF-Connecting-IP")||"unknown";
    const rateKey=await hash("admin-otp|"+email+"|"+ip);
    const now=Date.now(),cut=now-15*60*1000;
    await env.DB.prepare("DELETE FROM login_attempts WHERE attempted_at<?").bind(cut).run();
    const rate=await env.DB.prepare("SELECT COUNT(*) n FROM login_attempts WHERE attempt_key=? AND attempted_at>?").bind(rateKey,cut).first();
    if((rate?.n||0)>=3)return fail("Too many requests. Please wait 15 minutes before trying again.",429);
    if(action==="request"){
      await env.DB.prepare("INSERT INTO login_attempts(attempt_key,attempted_at) VALUES(?,?)").bind(rateKey,now).run();
      const user=await env.DB.prepare("SELECT id FROM users WHERE email=? AND role='admin' AND status='approved' LIMIT 1").bind(email).first();
      if(!user)return response({ok:true,message:"If this is the registered Team Lead email, a verification code will be sent."});
      const otp=randomOtp(),salt=randomSalt();
      await env.DB.prepare("DELETE FROM admin_password_otps WHERE user_id=?").bind(user.id).run();
      await env.DB.prepare("INSERT INTO admin_password_otps(id,user_id,otp_salt,otp_hash,expires_at,attempts,created_at) VALUES(?,?,?,?,?,0,?)")
        .bind(crypto.randomUUID(),user.id,salt,await hash(salt+":"+otp),now+10*60*1000,now).run();
      try{await sendOtp(env,email,otp);}catch(e){
        await env.DB.prepare("DELETE FROM admin_password_otps WHERE user_id=?").bind(user.id).run();
        return fail("Email could not be sent. Check the email service setup and try again.",502);
      }
      return response({ok:true,message:"If this is the registered Team Lead email, a verification code will be sent."});
    }
    if(action==="verify"){
      const otp=String(d?.otp||"").trim();
      if(!/^\\d{6}$/.test(otp))return fail("Enter the 6-digit verification code.");
      if(!passOK(d?.newPassword))return fail("New password must be 12–128 characters.");
      const user=await env.DB.prepare("SELECT id FROM users WHERE email=? AND role='admin' AND status='approved' LIMIT 1").bind(email).first();
      if(!user)return fail("Verification failed or code expired.",400);
      const record=await env.DB.prepare("SELECT id,otp_salt,otp_hash,expires_at,attempts FROM admin_password_otps WHERE user_id=? ORDER BY created_at DESC LIMIT 1").bind(user.id).first();
      if(!record || record.expires_at<=now || record.attempts>=5)return fail("Verification failed or code expired.",400);
      const valid=await hash(record.otp_salt+":"+otp)===record.otp_hash;
      if(!valid){
        await env.DB.prepare("UPDATE admin_password_otps SET attempts=attempts+1 WHERE id=?").bind(record.id).run();
        return fail("Incorrect code. Check the email and try again.",400);
      }
      const h=await passwordHash(d.newPassword);
      await env.DB.prepare("UPDATE users SET password_hash=?,password_salt=?,password_iterations=?,must_change_password=0,updated_at=? WHERE id=? AND role='admin' AND status='approved'")
        .bind(h.hash,h.salt,h.iterations,now,user.id).run();
      await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(user.id).run();
      await env.DB.prepare("DELETE FROM admin_password_otps WHERE user_id=?").bind(user.id).run();
      await env.DB.prepare("DELETE FROM login_attempts WHERE attempt_key=?").bind(rateKey).run();
      return response({ok:true,message:"Password reset successful. Sign in with your new password."});
    }
    return fail("Invalid request.");
  }catch(e){
    console.error("Admin email OTP failed",e?.message||e);
    return fail("Password reset could not be completed. Please try again later.",500);
  }
}
