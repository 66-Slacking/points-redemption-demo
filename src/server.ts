import 'dotenv/config';
import { Pool } from 'pg';
import { createApp } from './app';

if (!process.env.DATABASE_URL) throw new Error('请先在 .env 中设置 DATABASE_URL');
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const app = createApp(pool, {
  apiKey: process.env.DIGITAL_GOODS_API_KEY ?? '',
  apiBaseUrl: process.env.DIGITAL_GOODS_API_BASE_URL ?? 'https://digital-goods-api.vercel.app/api/v1'
});
const port = Number(process.env.PORT ?? 3000);
app.listen(port, '127.0.0.1', () => console.log(`本地网站已启动：http://127.0.0.1:${port}`));
