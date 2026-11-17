function readCookie(req){const v=(req.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith("hrh_session="));return v?v.slice(12):""}
async function digest(s){const b=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(s));return btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}
export async function onRequest({request,env,next}){
 const url=new URL(request.url),path=url.pathname;
 if(path.startsWith("/api/")||(path==="/login.html"||path==="/login")||path==="/favicon.ico")return next();
 const token=readCookie(request);
 if(!token)return Response.redirect(new URL("/login.html",url),302);
 const user=await env.DB.prepare("SELECT u.role,u.must_change_password FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.status='approved'").bind(await digest(token),Date.now()).first();
 if(!user)return Response.redirect(new URL("/login.html",url),302);
 if(user.must_change_password)return Response.redirect(new URL("/login.html?force=1",url),302);
 if(path==="/admin.html"&&user.role!=="admin")return Response.redirect(new URL("/",url),302);
 return next();
}
