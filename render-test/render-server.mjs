import {createServer} from 'node:http';
import {Readable} from 'node:stream';
import pg from 'pg';
import app from './app.mjs';

if (!process.env.DATABASE_URL) throw Error('DATABASE_URL is required');
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
      res.writeHead(state?200:503);return res.end(state?'ready':'snapshot required');
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
