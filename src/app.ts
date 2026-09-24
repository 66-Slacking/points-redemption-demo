import express, { NextFunction, Request, Response } from 'express';
import { createHash, randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { resolve } from 'node:path';
import { Pool, PoolClient } from 'pg';

const scrypt = promisify(scryptCallback);
const sevenDays = 7 * 24 * 60 * 60 * 1000;
type User = { id: string; username: string };
type Order = { request_id: string; user_id: string; product_id: string; price: number; status: string; code: string | null; last_error: string | null; retry_after: Date | null; key_fingerprint: string; created_at: Date };
export type Config = { apiKey: string; apiBaseUrl: string };

const hash = (text: string) => createHash('sha256').update(text).digest('hex');
const html = (value: unknown) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!);
const statusName = (status: string) => ({ processing: '处理中', delivered: '成功', failed: '失败' })[status as 'processing' | 'delivered' | 'failed'] ?? status;

function page(title: string, body: string, user?: User) {
  const nav = user ? `<nav>你好，${html(user.username)}　<a href="/">首页</a>　<form action="/logout" method="post"><button>退出登录</button></form></nav>` : '<nav><a href="/login">登录</a>　<a href="/register">注册</a></nav>';
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${html(title)}</title><link rel="stylesheet" href="/style.css"></head><body><main>${nav}<h1>${html(title)}</h1>${body}</main></body></html>`;
}

async function transaction<T>(pool: Pool, work: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

export async function passwordHash(password: string) {
  const salt = randomBytes(16).toString('hex');
  const result = await scrypt(password, salt, 64) as Buffer;
  return `${salt}:${result.toString('hex')}`;
}

async function passwordMatches(password: string, stored: string) {
  const [salt, expectedHex] = stored.split(':');
  if (!salt || !expectedHex) return false;
  const actual = await scrypt(password, salt, 64) as Buffer;
  const expected = Buffer.from(expectedHex, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function createApp(pool: Pool, config: Config) {
  const app = express();
  app.disable('x-powered-by');
  app.use((_req, res, next) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Content-Security-Policy', "default-src 'self'; style-src 'self'; form-action 'self'; base-uri 'none'");
    next();
  });
  app.use(express.static(resolve('public')));
  app.use(express.urlencoded({ extended: false, limit: '10kb' }));
  app.use((req, res, next) => {
    const origin = req.get('origin');
    if (req.method === 'POST' && origin && new URL(origin).host !== req.get('host')) return res.status(403).send('请求来源不正确');
    next();
  });
  app.use(async (req, res, next) => {
    const token = req.headers.cookie?.match(/(?:^|;\s*)sid=([a-f0-9]{64})(?:;|$)/)?.[1];
    if (token) {
      const result = await pool.query<User>('SELECT users.id, users.username FROM sessions JOIN users ON users.id = sessions.user_id WHERE token_hash = $1 AND expires_at > now()', [hash(token)]);
      res.locals.user = result.rows[0];
    }
    next();
  });
  const currentUser = (res: Response) => res.locals.user as User | undefined;
  const requireUser = (_req: Request, res: Response, next: NextFunction) => currentUser(res) ? next() : res.redirect('/login');

  async function signIn(res: Response, userId: string) {
    const token = randomBytes(32).toString('hex');
    await pool.query('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, now() + interval \'7 days\')', [hash(token), userId]);
    res.cookie('sid', token, { httpOnly: true, sameSite: 'lax', maxAge: sevenDays });
  }

  app.get('/register', (_req, res) => res.send(page('注册', '<form method="post"><label>用户名 <input name="username" required minlength="3" maxlength="24"></label><label>密码 <input name="password" type="password" required minlength="8"></label><button>注册</button></form>')));
  app.post('/register', async (req, res) => {
    const username = String(req.body.username ?? '').trim();
    const password = String(req.body.password ?? '');
    if (!/^[A-Za-z0-9_]{3,24}$/.test(username) || password.length < 8) return res.status(400).send(page('注册失败', '<p>用户名需为 3～24 位英文字母、数字或下划线；密码至少 8 位。</p><a href="/register">返回注册</a>'));
    try {
      const result = await pool.query<{ id: string }>('INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id', [username, await passwordHash(password)]);
      await signIn(res, result.rows[0].id);
      res.redirect('/');
    } catch (error) {
      if ((error as { code?: string }).code === '23505') return res.status(409).send(page('注册失败', '<p>用户名已存在。</p><a href="/register">返回注册</a>'));
      throw error;
    }
  });
  app.get('/login', (_req, res) => res.send(page('登录', '<form method="post"><label>用户名 <input name="username" required></label><label>密码 <input name="password" type="password" required></label><button>登录</button></form>')));
  app.post('/login', async (req, res) => {
    const result = await pool.query<{ id: string; password_hash: string }>('SELECT id, password_hash FROM users WHERE username = $1', [String(req.body.username ?? '')]);
    if (!result.rows[0] || !await passwordMatches(String(req.body.password ?? ''), result.rows[0].password_hash)) return res.status(401).send(page('登录失败', '<p>用户名或密码错误。</p><a href="/login">返回登录</a>'));
    await signIn(res, result.rows[0].id);
    res.redirect('/');
  });
  app.post('/logout', async (req, res) => {
    const token = req.headers.cookie?.match(/(?:^|;\s*)sid=([a-f0-9]{64})(?:;|$)/)?.[1];
    if (token) await pool.query('DELETE FROM sessions WHERE token_hash = $1', [hash(token)]);
    res.clearCookie('sid');
    res.redirect('/login');
  });

  app.get('/', requireUser, async (req, res) => {
    const user = currentUser(res)!;
    const [balance, tasks, products, ledger, orders] = await Promise.all([
      pool.query<{ balance: number }>('SELECT COALESCE(SUM(delta), 0)::int AS balance FROM ledger WHERE user_id = $1', [user.id]),
      pool.query<{ id: number; title: string; points: number; claimed: boolean }>('SELECT tasks.*, EXISTS (SELECT 1 FROM task_claims WHERE user_id = $1 AND task_id = tasks.id) AS claimed FROM tasks ORDER BY id', [user.id]),
      pool.query<{ product_id: string; title: string; price: number }>('SELECT * FROM products ORDER BY price', []),
      pool.query<{ id: string; kind: string; delta: number; created_at: Date }>('SELECT id, kind, delta, created_at FROM ledger WHERE user_id = $1 ORDER BY id DESC LIMIT 20', [user.id]),
      pool.query<Order>('SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20', [user.id])
    ]);
    const messages: Record<string, string> = { claimed: '任务积分已到账。', repeated: '这个任务已经领过积分。', low: '积分不足，无法兑换。', no_key: '尚未配置外部 API Key，不能兑换。', invalid: '请求无效。' };
    const notice = typeof req.query.msg === 'string' ? messages[req.query.msg] : undefined;
    const taskList = tasks.rows.map((task) => `<li>${html(task.title)}：+${task.points} 分 ${task.claimed ? '（已领取）' : `<form method="post" action="/tasks/${task.id}/claim"><button>完成并领取</button></form>`}</li>`).join('');
    const productList = products.rows.map((product) => `<li>${html(product.title)}：${product.price} 分 <form method="post" action="/redeem"><input type="hidden" name="productId" value="${html(product.product_id)}"><input type="hidden" name="requestId" value="o-${randomUUID()}"><button>兑换</button></form></li>`).join('');
    const ledgerNames: Record<string, string> = { task_reward: '任务奖励', redeem_spend: '兑换支出', redeem_refund: '兑换退回' };
    const ledgerList = ledger.rows.map((item) => `<li>${html(item.created_at.toLocaleString('zh-CN'))}　${html(ledgerNames[item.kind])}　${item.delta > 0 ? '+' : ''}${item.delta}</li>`).join('') || '<li>暂无记录</li>';
    const orderList = orders.rows.map((order) => `<li><a href="/orders/${html(order.request_id)}">${html(order.product_id)} · ${html(statusName(order.status))} · ${order.price} 分</a></li>`).join('') || '<li>暂无兑换</li>';
    res.send(page('积分兑换演示', `${notice ? `<p class="notice">${html(notice)}</p>` : ''}<section><h2>积分余额：${balance.rows[0].balance}</h2></section><section><h2>任务</h2><ul>${taskList}</ul></section><section><h2>商品</h2><ul>${productList}</ul></section><section><h2>积分收支</h2><ul>${ledgerList}</ul></section><section><h2>兑换记录</h2><ul>${orderList}</ul></section>`, user));
  });

  app.post('/tasks/:id/claim', requireUser, async (req, res) => {
    const user = currentUser(res)!;
    const taskId = Number(req.params.id);
    if (!Number.isSafeInteger(taskId)) return res.redirect('/?msg=invalid');
    const outcome = await transaction(pool, async (client) => {
      await client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [user.id]);
      const task = await client.query<{ points: number }>('SELECT points FROM tasks WHERE id = $1', [taskId]);
      if (!task.rows[0]) return 'invalid';
      const claim = await client.query<{ id: string }>('INSERT INTO task_claims (user_id, task_id) VALUES ($1, $2) ON CONFLICT (user_id, task_id) DO NOTHING RETURNING id', [user.id, taskId]);
      if (!claim.rows[0]) return 'repeated';
      await client.query('INSERT INTO ledger (user_id, kind, reference_id, delta) VALUES ($1, $2, $3, $4)', [user.id, 'task_reward', claim.rows[0].id, task.rows[0].points]);
      return 'claimed';
    });
    res.redirect(`/?msg=${outcome}`);
  });

  async function finishOrder(requestId: string, code?: string) {
    await transaction(pool, async (client) => {
      const order = await client.query<Order>('SELECT * FROM orders WHERE request_id = $1 FOR UPDATE', [requestId]);
      if (order.rows[0]?.status !== 'processing') return;
      if (code) {
        await client.query("UPDATE orders SET status = 'delivered', code = $2, last_error = NULL, updated_at = now() WHERE request_id = $1", [requestId, code]);
      } else {
        await client.query("UPDATE orders SET status = 'failed', last_error = '商品不可用，积分已退回', updated_at = now() WHERE request_id = $1", [requestId]);
        await client.query('INSERT INTO ledger (user_id, kind, reference_id, delta) VALUES ($1, $2, $3, $4)', [order.rows[0].user_id, 'redeem_refund', requestId, order.rows[0].price]);
      }
    });
  }

  async function keepPending(requestId: string, reason: string, seconds = 30) {
    await pool.query("UPDATE orders SET last_error = $2, retry_after = now() + ($3::int * interval '1 second'), updated_at = now() WHERE request_id = $1 AND status = 'processing'", [requestId, reason, seconds]);
  }

  async function apiCall(method: 'GET' | 'POST', path: string, body?: object) {
    return fetch(`${config.apiBaseUrl.replace(/\/$/, '')}${path}`, {
      method,
      headers: { Authorization: `Bearer ${config.apiKey}`, 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(8000)
    });
  }

  async function processOrder(requestId: string) {
    const client = await pool.connect();
    let locked = false;
    try {
      const lock = await client.query<{ locked: boolean }>('SELECT pg_try_advisory_lock(73125, hashtext($1)) AS locked', [requestId]);
      locked = lock.rows[0].locked;
      if (!locked) return;
      const result = await client.query<Order>('SELECT * FROM orders WHERE request_id = $1', [requestId]);
      const order = result.rows[0];
      if (!order || order.status !== 'processing' || (order.retry_after && order.retry_after > new Date())) return;
      if (order.key_fingerprint !== hash(config.apiKey)) return keepPending(requestId, 'API Key 已变化；请人工核对原兑换结果，避免重复发码', 3600);
      let response: globalThis.Response;
      try {
        response = await apiCall('GET', `/deliveries/${requestId}`);
        if (response.status === 404) response = await apiCall('POST', '/deliveries', { requestId, productId: order.product_id });
      } catch {
        return keepPending(requestId, '外部服务超时或网络异常，结果待确认');
      }
      if (response.status === 200) {
        const data = await response.json().catch(() => null) as { requestId?: string; productId?: string; status?: string; code?: string } | null;
        if (data?.requestId === requestId && data.productId === order.product_id && data.status === 'delivered' && typeof data.code === 'string' && data.code) return finishOrder(requestId, data.code);
        return keepPending(requestId, '外部服务响应格式异常，结果待确认');
      }
      if (response.status === 422) return finishOrder(requestId);
      const wait = response.status === 429 ? Math.min(Number(response.headers.get('retry-after')) || 60, 3600) : 30;
      return keepPending(requestId, `外部服务返回 HTTP ${response.status}，稍后可重试`, wait);
    } finally {
      if (locked) await client.query('SELECT pg_advisory_unlock(73125, hashtext($1))', [requestId]);
      client.release();
    }
  }

  app.post('/redeem', requireUser, async (req, res) => {
    if (!config.apiKey) return res.redirect('/?msg=no_key');
    const user = currentUser(res)!;
    const requestId = String(req.body.requestId ?? '');
    const productId = String(req.body.productId ?? '');
    if (!/^o-[0-9a-f-]{36}$/.test(requestId)) return res.redirect('/?msg=invalid');
    const outcome = await transaction(pool, async (client) => {
      await client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [user.id]);
      const previous = await client.query<Order>('SELECT * FROM orders WHERE request_id = $1', [requestId]);
      if (previous.rows[0]) return previous.rows[0].user_id === user.id && previous.rows[0].product_id === productId ? 'existing' : 'invalid';
      const product = await client.query<{ price: number }>('SELECT price FROM products WHERE product_id = $1', [productId]);
      if (!product.rows[0]) return 'invalid';
      const balance = await client.query<{ balance: number }>('SELECT COALESCE(SUM(delta), 0)::int AS balance FROM ledger WHERE user_id = $1', [user.id]);
      if (balance.rows[0].balance < product.rows[0].price) return 'low';
      await client.query("INSERT INTO orders (request_id, user_id, product_id, price, key_fingerprint, status) VALUES ($1, $2, $3, $4, $5, 'processing')", [requestId, user.id, productId, product.rows[0].price, hash(config.apiKey)]);
      await client.query('INSERT INTO ledger (user_id, kind, reference_id, delta) VALUES ($1, $2, $3, $4)', [user.id, 'redeem_spend', requestId, -product.rows[0].price]);
      return 'created';
    });
    if (outcome === 'low' || outcome === 'invalid') return res.redirect(`/?msg=${outcome}`);
    await processOrder(requestId).catch(console.error);
    res.redirect(`/orders/${requestId}`);
  });

  app.get('/orders/:id', requireUser, async (req, res) => {
    const user = currentUser(res)!;
    const result = await pool.query<Order>('SELECT * FROM orders WHERE request_id = $1 AND user_id = $2', [req.params.id, user.id]);
    const order = result.rows[0];
    if (!order) return res.status(404).send(page('未找到兑换记录', '<a href="/">返回首页</a>', user));
    const detail = `<p>商品：${html(order.product_id)}　花费：${order.price} 分</p><p>状态：${html(statusName(order.status))}</p>${order.code ? `<p>兑换码：<strong>${html(order.code)}</strong></p>` : ''}${order.last_error ? `<p class="notice">${html(order.last_error)}</p>` : ''}${order.status === 'processing' ? `<form method="post" action="/orders/${html(order.request_id)}/retry"><button>查询并重试</button></form>` : ''}<p><a href="/">返回首页</a></p>`;
    res.send(page('兑换详情', detail, user));
  });
  app.post('/orders/:id/retry', requireUser, async (req, res) => {
    const user = currentUser(res)!;
    const result = await pool.query<Order>('SELECT * FROM orders WHERE request_id = $1 AND user_id = $2', [req.params.id, user.id]);
    if (!result.rows[0]) return res.status(404).send('未找到兑换记录');
    await processOrder(result.rows[0].request_id).catch(console.error);
    res.redirect(`/orders/${result.rows[0].request_id}`);
  });
  app.use((error: Error, _req: Request, res: Response, _next: NextFunction) => {
    console.error(error);
    res.status(500).send(page('服务暂时出错', '<p>请稍后重试；已提交的兑换可在记录中查看。</p><a href="/">返回首页</a>', currentUser(res)));
  });
  return app;
}
