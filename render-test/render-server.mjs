import {createServer} from 'node:http';
import {Readable} from 'node:stream';
import {createHash,timingSafeEqual} from 'node:crypto';
import pg from 'pg';
import app from './app.mjs';

if (!process.env.DATABASE_URL) throw Error('DATABASE_URL is required');
const secretMatches=(value,expected)=>Boolean(expected)&&timingSafeEqual(createHash('sha256').update(value||'').digest(),createHash('sha256').update(expected).digest());
const pool = new pg.Pool({connectionString:process.env.DATABASE_URL,max:4});
await pool.query(`CREATE TABLE IF NOT EXISTS vivah_app_state (
  id text PRIMARY KEY, revision bigint NOT NULL DEFAULT 1, state jsonb NOT NULL
)`);
const BUCKET = {
  async get(id) {
    const {rows:[row]}=await pool.query('SELECT revision, state FROM vivah_app_state WHERE id=$1',[id]);
    return row ? {etag:row.revision,json:async()=>row.state} : null;
  },
  async put(id,state,{onlyIf}) {
    if(onlyIf.etagMatches===undefined)return null;
    const {rows:[row]}=await pool.query(
      'UPDATE vivah_app_state SET state=$2, revision=revision+1 WHERE id=$1 AND revision=$3 RETURNING revision',
      [id,state,onlyIf.etagMatches]
    );
    return row ? {etag:row.revision} : null;
  }
};
createServer(async (req,res)=>{
  try {
    const base='https://'+(process.env.RENDER_EXTERNAL_HOSTNAME||'localhost');
    const url=new URL(req.url,base);
    if(url.origin!==base){res.writeHead(400);return res.end();}
    if(url.pathname==='/health'){
      await pool.query('SELECT 1');
      const state=await BUCKET.get('vivah-state.json');
      res.writeHead(200);return res.end(state?'ready':'waiting for data');
    }
    if(url.pathname==='/_migration/import'){
      if(req.method!=='POST'||!secretMatches(req.headers.authorization,'Bearer '+(process.env.VIVAH_IMPORT_TOKEN||'invalid-disabled'))||!process.env.VIVAH_IMPORT_TOKEN){res.writeHead(404);return res.end();}
      const chunks=[];
      let length=0;
      for await(const chunk of req){
        length+=chunk.length;
        if(length>8*1024*1024){res.writeHead(413);return res.end();}
        chunks.push(chunk);
      }
      let state;
      try{state=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{res.writeHead(400);return res.end();}
      if(!state?.admin?.digest||!state.admin.salt||!Array.isArray(state.users)||!Array.isArray(state.venues)||!Array.isArray(state.requests)){res.writeHead(422);return res.end();}
      state.sessions={};
      const result=await pool.query('INSERT INTO vivah_app_state (id,state) VALUES ($1,$2) ON CONFLICT (id) DO NOTHING',['vivah-state.json',JSON.stringify(state)]);
      res.writeHead(result.rowCount===1?201:409,{'Content-Type':'application/json','Cache-Control':'no-store'});
      return res.end(JSON.stringify({users:state.users.length,venues:state.venues.length,bookings:state.requests.length}));
    }
    const gate=process.env.VIVAH_TEST_ACCESS_KEY;
    if(!gate||!secretMatches(req.headers.authorization,'Basic '+Buffer.from('vivah:'+gate).toString('base64'))){
      res.writeHead(401,{'WWW-Authenticate':'Basic realm="Vivah Venus private test"','Cache-Control':'no-store'});
      return res.end('Private test');
    }
    if(['/setup','/api/setup-admin'].includes(url.pathname)){res.writeHead(404);return res.end();}
    if(!await BUCKET.get('vivah-state.json')){res.writeHead(503);return res.end('Migration snapshot required');}
    const init={method:req.method,headers:req.headers};
    if(!['GET','HEAD'].includes(req.method)){init.body=Readable.toWeb(req);init.duplex='half';}
    const response=await app.fetch(new Request(url,init),{BUCKET});
    res.writeHead(response.status,Object.fromEntries(response.headers));
    if(response.body)Readable.fromWeb(response.body).pipe(res);else res.end();
  }catch{
    if(!res.headersSent)res.writeHead(503);
    res.end('Service unavailable');
  }
}).listen(Number(process.env.PORT||10000),'0.0.0.0');
