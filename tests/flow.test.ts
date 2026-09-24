import 'dotenv/config';
import assert from 'node:assert/strict';
import { createServer, Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { Pool } from 'pg';
import { createApp } from '../src/app';

test('注册、积分、并发兑换、外部故障与幂等恢复', async (t) => {
  if (!process.env.TEST_DATABASE_URL) throw new Error('请在 .env 中设置 TEST_DATABASE_URL，并初始化测试库');
  const pool = new Pool({ connectionString: process.env.TEST_DATABASE_URL });
  const deliveries = new Map<string, { requestId: string; productId: string; status: string; code: string }>();
  let mode: 'success' | 'unavailable' | 'lost_reply' = 'success';
  let created = 0;
  const mock = createServer(async (req, res) => {
    const id = req.url?.split('/').pop() ?? '';
    if (req.method === 'GET') {
      const delivery = deliveries.get(id);
      res.writeHead(delivery ? 200 : 404, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(delivery ?? { error: { code: 'NOT_FOUND' } }));
    }
    let body = '';
    for await (const chunk of req) body += chunk;
    const { requestId, productId } = JSON.parse(body);
    if (mode === 'unavailable') { res.writeHead(422); return res.end('{}'); }
    let delivery = deliveries.get(requestId);
    if (!delivery) {
      created++;
      delivery = { requestId, productId, status: 'delivered', code: `TEST-CODE-${created}` };
      deliveries.set(requestId, delivery);
    }
    if (mode === 'lost_reply') return req.socket.destroy();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(delivery));
  });
  const listen = (server: Server) => new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  await listen(mock);
  const mockPort = (mock.address() as AddressInfo).port;
  const web = createApp(pool, { apiKey: 'test-only-key', apiBaseUrl: `http://127.0.0.1:${mockPort}/api/v1` }).listen(0, '127.0.0.1');
  await new Promise<void>((resolve) => web.once('listening', resolve));
  const base = `http://127.0.0.1:${(web.address() as AddressInfo).port}`;
  t.after(async () => { web.closeAllConnections(); mock.closeAllConnections(); await new Promise<void>((resolve) => web.close(() => resolve())); await new Promise<void>((resolve) => mock.close(() => resolve())); await pool.end(); });

  const post = (path: string, cookie: string, data: Record<string, string> = {}) => fetch(base + path, { method: 'POST', headers: { cookie, 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(data), redirect: 'manual' });
  async function newUser() {
    const username = `u_${randomUUID().replace(/-/g, '').slice(0, 15)}`;
    const response = await post('/register', '', { username, password: 'password123' });
    assert.equal(response.status, 302);
    const cookie = response.headers.get('set-cookie')!.split(';')[0];
    const id = (await pool.query<{ id: string }>('SELECT id FROM users WHERE username = $1', [username])).rows[0].id;
    return { cookie, id };
  }
  async function claim(cookie: string, taskId: number) { return post(`/tasks/${taskId}/claim`, cookie); }
  async function requestId(cookie: string, product: string) {
    const dashboard = await (await fetch(base + '/', { headers: { cookie } })).text();
    const found = dashboard.match(new RegExp(`name="productId" value="${product}"><input type="hidden" name="requestId" value="([^"]+)"`));
    assert.ok(found);
    return found[1];
  }
  async function balance(userId: string) { return Number((await pool.query('SELECT COALESCE(SUM(delta), 0) AS n FROM ledger WHERE user_id = $1', [userId])).rows[0].n); }

  await t.test('任务只能领取一次；同一兑换请求只扣一次、发一次', async () => {
    const user = await newUser();
    await claim(user.cookie, 1); await claim(user.cookie, 1); await claim(user.cookie, 2);
    assert.equal(await balance(user.id), 50);
    const id = await requestId(user.cookie, 'ebook');
    await post('/redeem', user.cookie, { requestId: id, productId: 'ebook' });
    await post('/redeem', user.cookie, { requestId: id, productId: 'ebook' });
    assert.equal(await balance(user.id), 10);
    assert.equal(created, 1);
    const page = await (await fetch(base + `/orders/${id}`, { headers: { cookie: user.cookie } })).text();
    assert.match(page, /TEST-CODE-1/);
    const other = await newUser();
    const forbidden = await fetch(base + `/orders/${id}`, { headers: { cookie: other.cookie } });
    assert.equal(forbidden.status, 404);
    assert.doesNotMatch(await forbidden.text(), /TEST-CODE-1/);
  });

  await t.test('两个不同请求同时兑换，也不能把积分花成负数', async () => {
    const user = await newUser();
    await claim(user.cookie, 1); await claim(user.cookie, 2);
    const first = await requestId(user.cookie, 'ebook');
    const second = await requestId(user.cookie, 'ebook');
    await Promise.all([post('/redeem', user.cookie, { requestId: first, productId: 'ebook' }), post('/redeem', user.cookie, { requestId: second, productId: 'ebook' })]);
    assert.equal(await balance(user.id), 10);
    assert.equal(Number((await pool.query('SELECT count(*) AS n FROM orders WHERE user_id = $1', [user.id])).rows[0].n), 1);
  });

  await t.test('发码成功但回复丢失，按原编号查询后恢复', async () => {
    const user = await newUser();
    await claim(user.cookie, 1); await claim(user.cookie, 2);
    const id = await requestId(user.cookie, 'ebook');
    mode = 'lost_reply';
    const before = created;
    await post('/redeem', user.cookie, { requestId: id, productId: 'ebook' });
    assert.equal(await balance(user.id), 10);
    assert.equal((await pool.query('SELECT status FROM orders WHERE request_id = $1', [id])).rows[0].status, 'processing');
    await pool.query('UPDATE orders SET retry_after = now() - interval \'1 second\' WHERE request_id = $1', [id]);
    mode = 'success';
    await post(`/orders/${id}/retry`, user.cookie);
    assert.equal((await pool.query('SELECT status FROM orders WHERE request_id = $1', [id])).rows[0].status, 'delivered');
    assert.equal(created, before + 1);
    assert.equal(await balance(user.id), 10);
  });

  await t.test('商品不可用时，失败记录和退分各出现一次', async () => {
    const user = await newUser();
    await claim(user.cookie, 1); await claim(user.cookie, 2);
    const id = await requestId(user.cookie, 'theme');
    mode = 'unavailable';
    await post('/redeem', user.cookie, { requestId: id, productId: 'theme' });
    await post('/redeem', user.cookie, { requestId: id, productId: 'theme' });
    assert.equal((await pool.query('SELECT status FROM orders WHERE request_id = $1', [id])).rows[0].status, 'failed');
    assert.equal(await balance(user.id), 50);
    assert.equal(Number((await pool.query("SELECT count(*) AS n FROM ledger WHERE kind = 'redeem_refund' AND reference_id = $1", [id])).rows[0].n), 1);
  });
});
