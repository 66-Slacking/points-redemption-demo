import 'dotenv/config';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { Client } from 'pg';
import { passwordHash } from '../src/app';

async function main() {
  if (!process.env.DATABASE_URL) throw new Error('请先在 .env 中设置 DATABASE_URL');
  const client = new Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();
  try {
    const sql = await readFile(resolve('sql/schema.sql'), 'utf8');
    await client.query(sql);
    await client.query('INSERT INTO users (username, password_hash) VALUES ($1, $2) ON CONFLICT (username) DO NOTHING', ['demo', await passwordHash('demo12345')]);
    console.log('数据库表和演示数据已准备好。');
  } finally {
    await client.end();
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
