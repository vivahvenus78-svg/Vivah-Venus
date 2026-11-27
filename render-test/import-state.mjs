import {readFile} from 'node:fs/promises';
import pg from 'pg';

if(!process.env.DATABASE_URL||!process.argv[2])throw Error('Set DATABASE_URL and supply the protected R2 snapshot file');
const state=JSON.parse(await readFile(process.argv[2],'utf8'));
if(!state.admin?.digest||!state.admin?.salt||!Array.isArray(state.users)||!Array.isArray(state.venues)||!Array.isArray(state.requests))
  throw Error('Expected a Vivah Venus snapshot with an existing administrator');
state.sessions={};
const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,max:1});
try{
  await pool.query('CREATE TABLE IF NOT EXISTS vivah_app_state (id text PRIMARY KEY, revision bigint NOT NULL DEFAULT 1, state jsonb NOT NULL)');
  const result=await pool.query('INSERT INTO vivah_app_state (id,state) VALUES ($1,$2) ON CONFLICT (id) DO NOTHING',['vivah-state.json',JSON.stringify(state)]);
  if(result.rowCount!==1)throw Error('Import refused: the destination already contains a snapshot');
  console.log('Imported snapshot. Users must sign in again.');
}finally{await pool.end();}
