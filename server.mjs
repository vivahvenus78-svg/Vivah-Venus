import {createServer} from 'node:http';
import {readFileSync,writeFileSync,renameSync} from 'node:fs';
import {randomBytes,scryptSync,timingSafeEqual} from 'node:crypto';
const adminEmail=process.env.VIVAH_ADMIN_EMAIL?.trim().toLowerCase();
const secret=process.env.VIVAH_ADMIN_PASSWORD;
if(!adminEmail || !secret || secret.length<12) throw Error('Set VIVAH_ADMIN_EMAIL and VIVAH_ADMIN_PASSWORD (12+ characters).');
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
const adminSalt=randomBytes(16).toString('hex');
const adminHash=hash(secret,adminSalt);
const secure=process.env.VIVAH_SECURE_COOKIE==='1';
const cookie=(token,max)=>`vv=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${max}${secure?'; Secure':''}`;
function json(res,status,value){res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(value));}
const files={'/':['index.html','text/html; charset=utf-8'],'/index.html':['index.html','text/html; charset=utf-8'],'/manifest.webmanifest':['manifest.webmanifest','application/manifest+json'],'/icon-192.png':['icon-192.png','image/png'],'/icon-512.png':['icon-512.png','image/png']};
const failures=new Map();
const blocked=(ip)=>{
  const now=Date.now();
  for(const [key,value] of failures) if(value.until<now) failures.delete(key);
  return (failures.get(ip)?.count||0)>=12;
};
const bump=(ip)=>failures.set(ip,{count:(failures.get(ip)?.count||0)+1,until:Date.now()+600000});
createServer(async(req,res)=>{
  try{
    const path=new URL(req.url,'http://localhost').pathname;
    if(req.method==='GET'&&files[path]){
      const [name,type]=files[path];
      res.writeHead(200,{'Content-Type':type,'Cache-Control':'no-cache','X-Content-Type-Options':'nosniff'});return res.end(readFileSync(new URL('./public/'+name,import.meta.url)));
    }
    const token=/\bvv=([a-f0-9]{64})(?:;|$)/.exec(req.headers.cookie||'')?.[1];
    const session=token&&db.sessions[token];
    const user=session?.expires>Date.now()?session.user:null;
    if(req.method==='GET'&&path==='/api/state'){
      const venues=db.venues.filter(v=>v.status==='approved'||user?.role==='admin'||v.owner===user?.id);
      const requests=user?db.requests.filter(r=>user.role==='admin'||r.owner===user.id||r.customer===user.id):[];
      return json(res,200,{user,venues,requests});
    }
    if(req.method!=='POST'||!path.startsWith('/api/'))return json(res,404,{error:'à¤ªà¥‡à¤œ à¤¨à¤¹à¥€à¤‚ à¤®à¤¿à¤²à¤¾à¥¤'});
    if(!req.headers['content-type']?.startsWith('application/json')||req.headers['sec-fetch-site']==='cross-site')return json(res,403,{error:'à¤…à¤¨à¥à¤°à¥‹à¤§ à¤…à¤®à¤¾à¤¨à¥à¤¯ à¤¹à¥ˆà¥¤'});
    let raw='';
    for await(const chunk of req){raw+=chunk;if(raw.length>12000)return json(res,413,{error:'à¤…à¤¨à¥à¤°à¥‹à¤§ à¤¬à¤¹à¥à¤¤ à¤¬à¤¡à¤¼à¤¾ à¤¹à¥ˆà¥¤'});}
    let body;
    try{body=JSON.parse(raw);if(!body||typeof body!=='object')throw Error();}
    catch{return json(res,400,{error:'à¤…à¤¨à¥à¤°à¥‹à¤§ à¤…à¤®à¤¾à¤¨à¥à¤¯ à¤¹à¥ˆà¥¤'});}
    const next=structuredClone(db);
    if(path==='/api/login'||path==='/api/register'){
      const ip=req.socket.remoteAddress;
      if(blocked(ip))return json(res,429,{error:'à¤•à¥à¤› à¤¦à¥‡à¤° à¤¬à¤¾à¤¦ à¤¦à¥‹à¤¬à¤¾à¤°à¤¾ à¤•à¥‹à¤¶à¤¿à¤¶ à¤•à¤°à¥‡à¤‚à¥¤'});
      const {role,password}=body;
      const email=typeof body.email==='string'?body.email.trim().toLowerCase():'';
      if(!['admin','customer','owner'].includes(role)||typeof password!=='string'||password.length<8||password.length>128||email.length>180||!/^\S+@\S+\.\S+$/.test(email))return json(res,400,{error:'à¤¸à¤¹à¥€ à¤ˆà¤®à¥‡à¤² à¤”à¤° à¤•à¤® à¤¸à¥‡ à¤•à¤® 8 à¤…à¤•à¥à¤·à¤°à¥‹à¤‚ à¤•à¤¾ à¤ªà¤¾à¤¸à¤µà¤°à¥à¤¡ à¤¦à¥‡à¤‚à¥¤'});
      let account=next.users.find(u=>u.email===email);
      if(path==='/api/register'){
        if(role==='admin'||email===adminEmail||account)return json(res,409,{error:'à¤‡à¤¸ à¤–à¤¾à¤¤à¥‡ à¤•à¤¾ à¤°à¤œà¤¿à¤¸à¥à¤Ÿà¥à¤°à¥‡à¤¶à¤¨ à¤‰à¤ªà¤²à¤¬à¥à¤§ à¤¨à¤¹à¥€à¤‚ à¤¹à¥ˆà¥¤'});
        const salt=randomBytes(16).toString('hex');
        account={id:randomBytes(16).toString('hex'),role,email,salt,digest:hash(password,salt).toString('hex')};
        next.users.push(account);
      }else{
        const verified=role==='admin'
          ? email===adminEmail&&timingSafeEqual(hash(password,adminSalt),adminHash)
          : account?.role===role&&timingSafeEqual(hash(password,account.salt),Buffer.from(account.digest,'hex'));
        if(!verified){bump(ip);return json(res,401,{error:'à¤ˆà¤®à¥‡à¤², à¤ªà¤¾à¤¸à¤µà¤°à¥à¤¡ à¤¯à¤¾ à¤–à¤¾à¤¤à¥‡ à¤•à¤¾ à¤ªà¥à¤°à¤•à¤¾à¤° à¤—à¤²à¤¤ à¤¹à¥ˆà¥¤'});}
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
    if(!user)return json(res,401,{error:'à¤ªà¤¹à¤²à¥‡ à¤²à¥‰à¤—à¤¿à¤¨ à¤•à¤°à¥‡à¤‚à¥¤'});
    const deny=()=>json(res,403,{error:'à¤†à¤ªà¤•à¥‹ à¤‡à¤¸à¤•à¥€ à¤…à¤¨à¥à¤®à¤¤à¤¿ à¤¨à¤¹à¥€à¤‚ à¤¹à¥ˆà¥¤'});
    const invalid=()=>json(res,400,{error:'à¤œà¤¾à¤¨à¤•à¤¾à¤°à¥€ à¤œà¤¾à¤à¤šà¤•à¤° à¤¦à¥‹à¤¬à¤¾à¤°à¤¾ à¤•à¥‹à¤¶à¤¿à¤¶ à¤•à¤°à¥‡à¤‚à¥¤'});
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
    }else return json(res,404,{error:'à¤ªà¥‡à¤œ à¤¨à¤¹à¥€à¤‚ à¤®à¤¿à¤²à¤¾à¥¤'});
    save(next);return json(res,200,{ok:true});
  }catch(error){console.error(error);if(!res.headersSent)json(res,500,{error:'à¤¸à¤°à¥à¤µà¤° à¤ªà¤° à¤¸à¤®à¤¸à¥à¤¯à¤¾ à¤†à¤ˆà¥¤'});else res.end();}
}).listen(Number(process.env.PORT||8080),process.env.VIVAH_HOST||'127.0.0.1',()=>console.log('Vivah Venus is running.'));
