const Database = require('better-sqlite3');
const db = new Database('panel.db');

// Activar modo WAL para optimización de concurrencia
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT DEFAULT 'Revendedor',
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'reseller',
    balance REAL DEFAULT 0.0,
    must_change_password INTEGER DEFAULT 0,
    reset_token TEXT
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT CHECK(type IN ('Perfil', 'Cuenta', 'Combo')) NOT NULL,
    price REAL NOT NULL,
    image_url TEXT
  );

  CREATE TABLE IF NOT EXISTS stock (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    unique_code TEXT,
    product_id INTEGER,
    combo_data TEXT,
    platform_name TEXT,
    email_account TEXT NOT NULL,
    password_account TEXT NOT NULL,
    profile_name TEXT NOT NULL,
    status TEXT DEFAULT 'available',
    assigned_to_user_id INTEGER,
    purchase_date DATETIME,
    reseller_sale_price REAL DEFAULT 0.0,
    FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS support_tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    order_id INTEGER,
    subject TEXT NOT NULL,
    comment TEXT NOT NULL,
    image_url TEXT,
    status TEXT DEFAULT 'open',
    admin_comment TEXT,
    admin_image_url TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(order_id) REFERENCES stock(id)
  );

  CREATE TABLE IF NOT EXISTS recharge_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    receipt_url TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  );
`);

// Configuración inicial por defecto
const defaultSettings = [
  ['brand_name', 'CPANEL ANUBIS'],
  ['brand_logo', ''],
  ['brand_logo_size', 'h-10'],
  ['brand_display_mode', 'both'], // Options: text, logo, both
  ['bank_name', ''],
  ['bank_holder', ''],
  ['bank_account', ''],
  ['bank_concept', ''],
  ['payment_gateway_url', '']
];

defaultSettings.forEach(([key, val]) => {
  const check = db.prepare("SELECT value FROM settings WHERE key = ?").get(key);
  if (!check) {
    db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)").run(key, val);
  }
});

// Migraciones automáticas de seguridad
try { db.exec(`ALTER TABLE users ADD COLUMN name TEXT DEFAULT 'Revendedor';`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0;`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN reset_token TEXT;`); } catch (e) {}
try { db.exec(`ALTER TABLE stock ADD COLUMN unique_code TEXT;`); } catch (e) {}
try { db.exec(`ALTER TABLE stock ADD COLUMN combo_data TEXT;`); } catch (e) {}
try { db.exec(`ALTER TABLE stock ADD COLUMN purchase_date DATETIME;`); } catch (e) {}
try { db.exec(`ALTER TABLE stock ADD COLUMN reseller_sale_price REAL DEFAULT 0.0;`); } catch (e) {}
try { db.exec(`ALTER TABLE support_tickets ADD COLUMN admin_comment TEXT;`); } catch (e) {}
try { db.exec(`ALTER TABLE support_tickets ADD COLUMN admin_image_url TEXT;`); } catch (e) {}
try { db.exec(`ALTER TABLE support_tickets ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;`); } catch (e) {}

module.exports = db;