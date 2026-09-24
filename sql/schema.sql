CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY,
  title TEXT NOT NULL,
  points INTEGER NOT NULL CHECK (points > 0)
);

CREATE TABLE IF NOT EXISTS task_claims (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  task_id INTEGER NOT NULL REFERENCES tasks(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, task_id)
);

CREATE TABLE IF NOT EXISTS products (
  product_id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  price INTEGER NOT NULL CHECK (price > 0)
);

CREATE TABLE IF NOT EXISTS orders (
  request_id TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  product_id TEXT NOT NULL REFERENCES products(product_id),
  price INTEGER NOT NULL CHECK (price > 0),
  key_fingerprint TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('processing', 'delivered', 'failed')),
  code TEXT,
  last_error TEXT,
  retry_after TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK ((status = 'delivered' AND code IS NOT NULL) OR (status <> 'delivered' AND code IS NULL))
);

CREATE TABLE IF NOT EXISTS ledger (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL CHECK (kind IN ('task_reward', 'redeem_spend', 'redeem_refund')),
  reference_id TEXT NOT NULL,
  delta INTEGER NOT NULL CHECK (delta <> 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (kind, reference_id)
);

CREATE INDEX IF NOT EXISTS ledger_user_idx ON ledger(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS orders_user_idx ON orders(user_id, created_at DESC);

INSERT INTO tasks (id, title, points) VALUES
  (1, '阅读项目说明', 20),
  (2, '每日签到（演示任务）', 30),
  (3, '完成新手引导', 40)
ON CONFLICT (id) DO NOTHING;

INSERT INTO products (product_id, title, price) VALUES
  ('ebook', '电子手册兑换码', 40),
  ('course', '课程访问兑换码', 60),
  ('theme', '主题包兑换码', 30)
ON CONFLICT (product_id) DO NOTHING;
