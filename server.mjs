import {createServer} from 'node:http';
import {readFileSync,writeFileSync,renameSync} from 'node:fs';
import {createHash,randomBytes,scryptSync,timingSafeEqual} from 'node:crypto';
const legacyEmail=process.env.VIVAH_ADMIN_EMAIL?.trim().toLowerCase();
const legacyPassword=process.env.VIVAH_ADMIN_PASSWORD;
const setupCode=process.env.VIVAH_SETUP_CODE || '';
const requireEmail=value=>typeof value==='string'&&value.length<=180&&/^\S+@\S+.\S+$/.test(value);
const file=process.env.VIVAH_DATA_FILE || 'vivah-data.json';
let db;
try { db=JSON.parse(readFileSync(file,'utf8')); }
catch(error){ if(error.code!=='ENOENT') throw error; db={users:[],venues:[],requests:[],sessions:{}}; }
function save(next){
writeFileSync(file+'.tmp',JSON.stringify(next),{mode:0o600});
renameSync(file+'.tmp',file);
db=next;
}
const hash=(password,salt)=>scryptSync(password,salt,64);
function credentials(email,password){
const salt=randomBytes(16).toString('hex');
return {email,salt,digest:hash(password,salt).toString('hex')};
}
const legacyAdmin=requireEmail(legacyEmail)&&legacyPassword?.length>=12 ? credentials(legacyEmail,legacyPassword) : null;
const admin=()=>db.admin||legacyAdmin;
const setupEnabled=()=>!admin()&&setupCode.length>=32&&setupCode.length<=128;
if(!admin()&&!setupEnabled())throw Error('Set VIVAH_SETUP_CODE (32–128 characters) for first-time admin setup.');
const codeDigest=value=>createHash('sha256').update(value).digest();
const expectedCode=codeDigest(setupCode);
const secure=process.env.RENDER==='true'||process.env.VIVAH_SECURE_COOKIE==='1';
const cookie=(token,max)=>vv=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${max}${secure?'; Secure':''};
function json(res,status,value){res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(value));}
const files={'/':['index.html','text/html; charset=utf-8'],'/index.html':['index.html','text/html; charset=utf-8'],'/manifest.webmanifest':['manifest.webmanifest','application/manifest+json'],'/icon-192.png':['icon-192.png','image/png'],'/icon-512.png':['icon-512.png','image/png']};
const failures=new Map();
const blocked=(ip)=>{
const now=Date.now();
for(const [key,value] of failures) if(value.until<now) failures.delete(key);
return (failures.get(ip)?.count||0)>=12;
};
const bump=(ip)=>failures.set(ip,{count:(failures.get(ip)?.count||0)+1,until:Date.now()+600000});
const setupPage=`<!doctype html><html lang="hi"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Vivah Venus · एडमिन सेटअप</title>

<style>body{background:#24152b;color:#fff2e5;font:16px system-ui;margin:24px auto;padding:16px;max-width:460px}h1,a{color:#f6d996}form,label{display:grid;gap:8px}form{gap:16px}input,button{box-sizing:border-box;width:100%;padding:12px;font:inherit;border-radius:8px;border:1px solid #725e64}button{background:#edce8e;color:#24152b;font-weight:bold}</style>

<h1>Vivah Venus एडमिन सेटअप</h1>
<form id="setup" method="post" action="/api/setup-admin"><label>Setup Code<input name="code" type="password" autocomplete="off" minlength="32" maxlength="128" required></label>
<label>ईमेल<input name="email" type="email" autocomplete="username" maxlength="180" required></label>
<label>नया ऐप पासवर्ड<input name="password" type="password" autocomplete="new-password" minlength="12" maxlength="128" required></label>
<button>एडमिन खाता बनाएँ</button><p id="status" role="status"></p></form>
<a href="/#admin">एडमिन लॉगिन</a>
<script>
document.getElementById('setup').addEventListener('submit',async event=>{
  event.preventDefault();
  const form=event.currentTarget, button=form.querySelector('button'), status=document.getElementById('status');
  button.disabled=true;
  try {
    const response=await fetch('/api/setup-admin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.fromEntries(new FormData(form)))});
    if(!response.ok)throw Error((await response.json()).error);
    location.replace('/#admin');
  } catch(error) { status.textContent=error.message; button.disabled=false; }
});
</script></html>`;
let setupCooldown=0;
let setupFailures=0;
createServer(async(req,res)=>{
  try{
    const path=new URL(req.url,'http://localhost').pathname;
    if(req.method==='GET'&&path==='/setup'){
      if(!setupEnabled()){res.writeHead(303,{Location:'/#admin','Cache-Control':'no-store'});return res.end();}
      res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY'});
      return res.end(setupPage);
    }
    if(req.method==='GET'&&files[path]){
      const [name,type]=files[path];
      res.writeHead(200,{'Content-Type':type,'Cache-Control':'no-cache','X-Content-Type-Options':'nosniff'});return res.end(readFileSync(new URL('./public/'+name,import.meta.url)));
    }
    const token=/\bvv=([a-f0-9]{64})(?:;|$)/.exec(req.headers.cookie||'')?.[1];
    const sessionUser=()=>{const entry=token&&db.sessions[token];return entry?.expires>Date.now()?entry.user:null;};
    if(req.method==='GET'&&path==='/api/state'){
      const user=sessionUser();
      const venues=db.venues.filter(v=>v.status==='approved'||user?.role==='admin'||v.owner===user?.id);
      const requests=user?db.requests.filter(r=>user.role==='admin'||r.owner===user.id||r.customer===user.id):[];
      return json(res,200,{user,venues,requests});
    }
    if(req.method!=='POST'||!path.startsWith('/api/'))return json(res,404,{error:'पेज नहीं मिला।'});
    if(!req.headers['content-type']?.startsWith('application/json')||req.headers['sec-fetch-site']==='cross-site')return json(res,403,{error:'अनुरोध अमान्य है।'});
    let raw='';
    for await(const chunk of req){raw+=chunk;if(raw.length>12000)return json(res,413,{error:'अनुरोध बहुत बड़ा है।'});}
    let body;
    try{body=JSON.parse(raw);if(!body||typeof body!=='object')throw Error();}
    catch{return json(res,400,{error:'अनुरोध अमान्य है।'});}
    const next=structuredClone(db);
    if(path==='/api/setup-admin'){
      if(!setupEnabled())return json(res,409,{error:'एडमिन सेटअप बंद है।'});
      if(setupCooldown>Date.now())return json(res,429,{error:'कुछ देर बाद दोबारा कोशिश करें।'});
      const {code,password}=body;
      if(typeof code!=='string'||code.length>128||!timingSafeEqual(codeDigest(code),expectedCode)){
        if(++setupFailures>=12){setupCooldown=Date.now()+600000;setupFailures=0;}
        return json(res,403,{error:'Setup Code गलत है।'});
      }
      const email=typeof body.email==='string'?body.email.trim().toLowerCase():'';
      if(!requireEmail(email)||typeof password!=='string'||password.length<12||password.length>128)
        return json(res,400,{error:'सही ईमेल और कम से कम 12 अक्षरों का ऐप पासवर्ड दें।'});
      if(next.users.some(account=>account.email===email))
        return json(res,409,{error:'एडमिन के लिए अलग ईमेल इस्तेमाल करें।'});
      next.admin=credentials(email,password);
      save(next);
      return json(res,201,{ok:true});
    }
    if(path==='/api/login'||path==='/api/register'){
      const ip=req.socket.remoteAddress;
      if(blocked(ip))return json(res,429,{error:'कुछ देर बाद दोबारा कोशिश करें।'});
      const {role,password}=body;
      const email=typeof body.email==='string'?body.email.trim().toLowerCase():'';
      if(!['admin','customer','owner'].includes(role)||typeof password!=='string'||password.length<8||password.length>128||email.length>180||!/^\S+@\S+\.\S+$/.test(email))return json(res,400,{error:'सही ईमेल और कम से कम 8 अक्षरों का पासवर्ड दें।'});
      let account=next.users.find(u=>u.email===email);
      if(path==='/api/register'){
        if(role==='admin'||email===admin()?.email||account)return json(res,409,{error:'इस खाते का रजिस्ट्रेशन उपलब्ध नहीं है।'});
        const salt=randomBytes(16).toString('hex');
        account={id:randomBytes(16).toString('hex'),role,email,salt,digest:hash(password,salt).toString('hex')};
        next.users.push(account);
      }else{
        const verified=role==='admin'
          ? email===admin()?.email&&timingSafeEqual(hash(password,admin().salt),Buffer.from(admin().digest,"hex"))
          : account?.role===role&&timingSafeEqual(hash(password,account.salt),Buffer.from(account.digest,'hex'));
        if(!verified){bump(ip);return json(res,401,{error:'ईमेल, पासवर्ड या खाते का प्रकार गलत है।'});}
      }
      const id=randomBytes(32).toString('hex');
      if(token)delete next.sessions[token];
      for(const [key,value] of Object.entries(next.sessions))if(value.expires<=Date.now())delete next.sessions[key];
      next.sessions[id]={user:{id:role==='admin'?'admin':account.id,role},expires:Date.now()+86400000};
      save(next);res.setHeader('Set-Cookie',cookie(id,86400));return json(res,200,{ok:true});
    }
    if(path==='/api/logout'){
      if(token){delete next.sessions[token];save(next);}
      res.setHeader('Set-Cookie',cookie('',0));return json(res,200,{ok:true});
    }
    const user=sessionUser();
    if(!user)return json(res,401,{error:'पहले लॉगिन करें।'});
    const deny=()=>json(res,403,{error:'आपको इसकी अनुमति नहीं है।'});
    const invalid=()=>json(res,400,{error:'जानकारी जाँचकर दोबारा कोशिश करें।'});
    const id=()=>randomBytes(16).toString('hex');
    if(path==='/api/listing'){
      if(user.role!=='owner')return deny();
      const old=next.venues.find(v=>v.id===body.id);
      if(body.id&&old?.owner!==user.id)return deny();
      const {name,city,type,features,price,capacity}=body;
      if([name,city,type,features].some(v=>typeof v!=='string'||!v.trim()||v.length>200)||!Number.isSafeInteger(price)||price<1||price>1e9||!Number.isSafeInteger(capacity)||capacity<1||capacity>100000)return invalid();
      const venue={id:old?.id||id(),owner:user.id,status:'pending',name,city,type,features,price,capacity};
      if(old) Object.assign(old,venue); else next.venues.push(venue);
    }else if(path==='/api/review'){
      if(user.role!=='admin')return deny();
      const venue=next.venues.find(v=>v.id===body.id);
      if(!venue||!['approved','rejected'].includes(body.status))return invalid();
      venue.status=body.status;
    }else if(path==='/api/book'){
      if(user.role!=='customer')return deny();
      const venue=next.venues.find(v=>v.id===body.venueId&&v.status==='approved');
      const {name,date,guests}=body;
      const today=new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Kolkata',year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date());
      if(!venue||typeof name!=='string'||!name.trim()||name.length>80||typeof date!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(date)||date<today||!Number.isFinite(Date.parse(date))||new Date(date).toISOString().slice(0,10)!==date||!Number.isSafeInteger(guests)||guests<1||guests>venue.capacity)return invalid();
      next.requests.unshift({id:id(),venue:venue.name,owner:venue.owner,customer:user.id,name,date,guests,status:'new'});
    }else if(path==='/api/respond'){
      if(user.role!=='owner')return deny();
      const entry=next.requests.find(r=>r.id===body.id);
      if(!entry||entry.owner!==user.id)return deny();
      if(entry.status!=='new'||!['accepted','declined'].includes(body.status))return invalid();
      entry.status=body.status;
    }else return json(res,404,{error:'पेज नहीं मिला।'});
    save(next);return json(res,200,{ok:true});
  }catch(error){console.error(error);if(!res.headersSent)json(res,500,{error:'सर्वर पर समस्या आई।'});else res.end();}
}).listen(Number(process.env.PORT||8080),process.env.VIVAH_HOST||'127.0.0.1',()=>console.log('Vivah Venus is running.'));
