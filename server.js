require('dotenv').config();
const express = require('express');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const db = require('./database');

const app = express();

app.set('trust proxy', 1);

const JWT_SECRET = process.env.JWT_SECRET || 'Secret_Key_Default_Anubis_2026';

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// CREACIÓN DE LA TABLA DE INVENTARIO MAESTRO SI NO EXISTE
try {
  db.prepare(`
    CREATE TABLE IF NOT EXISTS master_inventory (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      platform_name TEXT NOT NULL,
      plan_type TEXT NOT NULL,
      email_account TEXT NOT NULL,
      password_account TEXT NOT NULL,
      supplier_name TEXT NOT NULL,
      total_profiles INTEGER NOT NULL,
      used_profiles INTEGER DEFAULT 0,
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
} catch (e) {
  console.error("Error creando tabla master_inventory:", e);
}

// CONFIGURACIÓN DE ENVÍO DE CORREO RECUPERACIÓN VÍA API HTTP BREVO
async function sendAdminRecoveryEmail(toEmail, tempPassword) {
  const brevoApiKey = process.env.BREVO_API_KEY || 'xkeysib-917acae54fd28a2b2d2fbb0f3c2ef353c9d2f272880';

  try {
    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'accept': 'application/json',
        'api-key': brevoApiKey,
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        sender: { name: "Soporte Cpanel Admin", email: "tanubistv@gmail.com" },
        to: [{ email: toEmail }],
        subject: "🔑 Recuperación de Contraseña de Administrador",
        htmlContent: `
          <div style="font-family: Arial, sans-serif; background-color: #0f172a; color: #ffffff; padding: 20px; border-radius: 10px;">
            <h2 style="color: #f59e0b;">Recuperación de Administrador</h2>
            <p>Has solicitado restablecer tu acceso como <strong>Administrador</strong> del panel.</p>
            <p>Tu contraseña temporal de acceso es:</p>
            <div style="background-color: #1e293b; padding: 15px; font-size: 22px; font-weight: bold; color: #10b981; letter-spacing: 2px; text-align: center; border-radius: 8px; margin: 15px 0;">
              ${tempPassword}
            </div>
            <p>Ingresa al panel con esta clave temporal y el sistema te pedirá definir tu nueva contraseña.</p>
            <hr style="border-color: #334155; margin-top: 20px;">
            <small style="color: #94a3b8;">Si no solicitaste este cambio, ignora este correo.</small>
          </div>
        `
      })
    });

    const result = await response.json();
    if (!response.ok) {
      console.error(`[ERROR RESPUESTA BREVO]:`, result);
    } else {
      console.log(`[CORREO ENVIADO VÍA BREVO A ${toEmail}]`, result);
    }
  } catch (err) {
    console.error(`[ERROR ENVIANDO CORREO BREVO] ${err.message}`);
  }
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  message: { error: 'Demasiados intentos fallidos. Inténtalo más tarde.' }
});

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }
});

function generateUnique8Code() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code = '';
  for (let i = 0; i < 8; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

function cleanupOldRechargeRequests() {
  try {
    const oldRequests = db.prepare("SELECT * FROM recharge_requests WHERE created_at <= datetime('now', '-48 hours') AND status != 'pending'").all();
    oldRequests.forEach(r => {
      if (r.receipt_url) {
        const fullPath = path.join(__dirname, r.receipt_url);
        if (fs.existsSync(fullPath)) {
          try { fs.unlinkSync(fullPath); } catch (e) {}
        }
      }
    });
    db.prepare("DELETE FROM recharge_requests WHERE created_at <= datetime('now', '-48 hours') AND status != 'pending'").run();
  } catch (err) {
    console.error("Error al limpiar solicitudes de pago antiguas:", err);
  }
}

// INVENTARIO MAESTRO Y PROVEEDORES (EXCLUSIVO ADMIN)
app.get('/api/admin/master-inventory', (req, res) => {
  try {
    const items = db.prepare("SELECT * FROM master_inventory ORDER BY id DESC").all();
    res.json(items);
  } catch (err) {
    res.status(500).json({ error: 'Error cargando inventario maestro: ' + err.message });
  }
});

app.post('/api/admin/master-inventory', (req, res) => {
  try {
    const { platformName, planType, emailAccount, passwordAccount, supplierName, totalProfiles } = req.body;
    if (!platformName || !emailAccount || !passwordAccount || !supplierName || !totalProfiles) {
      return res.status(400).json({ error: 'Todos los campos son obligatorios.' });
    }

    db.prepare(`
      INSERT INTO master_inventory (platform_name, plan_type, email_account, password_account, supplier_name, total_profiles, used_profiles)
      VALUES (?, ?, ?, ?, ?, ?, 0)
    `).run(platformName.trim(), planType || 'Mensual', emailAccount.trim(), passwordAccount.trim(), supplierName.trim(), parseInt(totalProfiles));

    res.json({ message: 'Cuenta guardada exitosamente en el Inventario Master.' });
  } catch (err) {
    res.status(500).json({ error: 'Error al registrar en inventario master: ' + err.message });
  }
});

app.post('/api/admin/verify-pass', (req, res) => {
  try {
    const { adminPassword } = req.body;
    const admin = db.prepare("SELECT * FROM users WHERE role = 'admin'").get();
    if (!admin || !bcrypt.compareSync(adminPassword, admin.password)) {
      return res.status(401).json({ error: 'Contraseña de Administrador incorrecta.' });
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Error verificando contraseña: ' + err.message });
  }
});

// BÚSQUEDA INSENSIBLE A MAYÚSCULAS/MINÚSCULAS
app.get('/api/admin/master-inventory/available/:platform', (req, res) => {
  try {
    const { platform } = req.params;
    const cleanSearch = (platform || '').trim().toLowerCase();

    const accounts = db.prepare(`
      SELECT * FROM master_inventory 
      WHERE (total_profiles - used_profiles) > 0 AND status = 'active'
      ORDER BY id ASC
    `).all();

    const matchedAccounts = accounts.filter(acc => {
      const accPlatform = (acc.platform_name || '').toLowerCase();
      return accPlatform.includes(cleanSearch) || cleanSearch.includes(accPlatform);
    });

    if (matchedAccounts.length === 0) {
      return res.status(404).json({ error: 'No hay cuentas disponibles en el Inventario Master para este servicio.' });
    }

    res.json(matchedAccounts);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener cuenta disponible: ' + err.message });
  }
});

app.delete('/api/admin/master-inventory/:id', (req, res) => {
  try {
    const { id } = req.params;
    db.prepare("DELETE FROM master_inventory WHERE id = ?").run(id);
    res.json({ message: 'Registro de Inventario Master eliminado correctamente.' });
  } catch (err) {
    res.status(500).json({ error: 'Error al eliminar registro: ' + err.message });
  }
});

// RUTAS EXCLUSIVAS DEL PANEL CREADOR
let creatorPassHash = bcrypt.hashSync("Anubis.123*", 10);
let creatorMustChangePass = false;

app.post('/api/creator/login', loginLimiter, (req, res) => {
  try {
    const { username, password } = req.body;
    if (username !== 'Anubistv' || !bcrypt.compareSync(password, creatorPassHash)) {
      return res.status(401).json({ error: 'Usuario o contraseña de Creador incorrectos.' });
    }
    res.json({ message: 'Login de Creador exitoso', mustChangePassword: creatorMustChangePass });
  } catch (err) {
    res.status(500).json({ error: 'Error en login de Creador: ' + err.message });
  }
});

app.post('/api/creator/forgot-password', (req, res) => {
  const tempPass = "RESET" + Math.floor(100000 + Math.random() * 900000);
  creatorPassHash = bcrypt.hashSync(tempPass, 10);
  creatorMustChangePass = true;
  console.log(`\n[CREADOR] CONTRASEÑA TEMPORAL CREADOR: ${tempPass}\n`);
  res.json({ message: 'Revisa la consola/logs del servidor para obtener tu contraseña temporal.' });
});

app.post('/api/creator/change-password', (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.trim().length < 6) {
    return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 6 caracteres.' });
  }
  creatorPassHash = bcrypt.hashSync(newPassword.trim(), 10);
  creatorMustChangePass = false;
  res.json({ message: 'Contraseña del Creador actualizada correctamente.' });
});

app.get('/api/creator/admins', (req, res) => {
  try {
    const admins = db.prepare("SELECT id, name, email, role, must_change_password FROM users WHERE role = 'admin'").all();
    res.json(admins);
  } catch (err) {
    res.status(500).json({ error: 'Error cargando administradores.' });
  }
});

app.post('/api/creator/setup-admin', (req, res) => {
  const { name, email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Ingresa correo y contraseña para el Administrador.' });

  try {
    const cleanEmail = email.trim().toLowerCase();
    const cleanName = (name || 'Administrador').trim();
    const hashedPassword = bcrypt.hashSync(password.trim(), 10);
    const existingAdmin = db.prepare("SELECT * FROM users WHERE email = ?").get(cleanEmail);

    if (existingAdmin) {
      db.prepare("UPDATE users SET name = ?, password = ?, role = 'admin', must_change_password = 1 WHERE id = ?").run(cleanName, hashedPassword, existingAdmin.id);
      res.json({ message: `Cuenta de Administrador actualizada correctamente para ${cleanEmail}` });
    } else {
      db.prepare("INSERT INTO users (name, email, password, role, balance, must_change_password) VALUES (?, ?, ?, 'admin', 0.0, 1)").run(cleanName, cleanEmail, hashedPassword);
      res.json({ message: `Nuevo Administrador registrado exitosamente: ${cleanEmail}` });
    }
  } catch (err) {
    res.status(500).json({ error: 'Error al configurar Administrador: ' + err.message });
  }
});

app.delete('/api/creator/delete-admin/:id', (req, res) => {
  const { id } = req.params;
  try {
    const target = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'admin'").get(id);
    if (!target) return res.status(404).json({ error: 'Administrador no encontrado.' });

    const deleteTransaction = db.transaction(() => {
      db.prepare('UPDATE stock SET assigned_to_user_id = NULL WHERE assigned_to_user_id = ?').run(id);
      db.prepare('DELETE FROM support_tickets WHERE user_id = ?').run(id);
      db.prepare('DELETE FROM users WHERE id = ?').run(id);
    });
    deleteTransaction();
    res.json({ message: `Administrador ${target.email} eliminado correctamente.` });
  } catch (err) {
    res.status(500).json({ error: 'Error eliminando administrador: ' + err.message });
  }
});

// CONFIGURACIÓN DE BRANDING, SETTINGS Y TÉRMINOS
app.get('/api/settings', (req, res) => {
  try {
    cleanupOldRechargeRequests();
    const settings = db.prepare("SELECT key, value FROM settings").all();
    const config = {};
    settings.forEach(s => config[s.key] = s.value);
    res.json(config);
  } catch (err) {
    res.status(500).json({ error: 'Error obteniendo configuración.' });
  }
});

app.post('/api/admin/settings', upload.fields([
  { name: 'brandLogoFile', maxCount: 1 },
  { name: 'termsImageFile', maxCount: 1 }
]), (req, res) => {
  try {
    const { 
      brandName, brandLogoUrl, brandLogoSize, brandDisplayMode, deleteLogo, 
      bankName, bankHolder, bankAccount, bankConcept, paymentGatewayUrl,
      termsText, termsImageUrl
    } = req.body;
    
    const saveSetting = db.prepare(`
      INSERT INTO settings (key, value) VALUES (?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `);

    if (brandName) saveSetting.run('brand_name', brandName.trim());
    if (bankName !== undefined) saveSetting.run('bank_name', bankName.trim());
    if (bankHolder !== undefined) saveSetting.run('bank_holder', bankHolder.trim());
    if (bankAccount !== undefined) saveSetting.run('bank_account', bankAccount.trim());
    if (bankConcept !== undefined) saveSetting.run('bank_concept', bankConcept.trim());
    if (paymentGatewayUrl !== undefined) saveSetting.run('payment_gateway_url', paymentGatewayUrl.trim());
    if (brandLogoSize !== undefined) saveSetting.run('brand_logo_size', brandLogoSize.trim());
    if (brandDisplayMode !== undefined) saveSetting.run('brand_display_mode', brandDisplayMode.trim());

    if (termsText !== undefined) saveSetting.run('terms_text', termsText.trim());

    if (req.files && req.files['termsImageFile']) {
      saveSetting.run('terms_image', '/uploads/' + req.files['termsImageFile'][0].filename);
    } else if (termsImageUrl !== undefined && termsImageUrl.trim() !== '') {
      saveSetting.run('terms_image', termsImageUrl.trim());
    }

    if (deleteLogo === 'true') {
      saveSetting.run('brand_logo', '');
    } else {
      let logoVal = (brandLogoUrl || '').trim();
      if (req.files && req.files['brandLogoFile']) {
        logoVal = '/uploads/' + req.files['brandLogoFile'][0].filename;
      }
      if (logoVal !== '') {
        saveSetting.run('brand_logo', logoVal);
      }
    }

    res.json({ message: 'Configuración y Términos actualizados correctamente.' });
  } catch (dbErr) {
    console.error("Error guardando settings:", dbErr);
    res.status(500).json({ error: 'Error en la base de datos: ' + dbErr.message });
  }
});

// LOGIN GENERAL
app.post('/api/login', loginLimiter, (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = (email || '').trim().toLowerCase();
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail);

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }

    const userData = {
      id: user.id,
      name: user.name || 'Administrador',
      email: user.email,
      role: user.role,
      balance: user.balance,
      mustChangePassword: user.must_change_password === 1
    };

    const token = jwt.sign(userData, JWT_SECRET, { expiresIn: '24h' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000
    });

    res.json({ message: 'Login exitoso', user: userData });
  } catch (err) {
    res.status(500).json({ error: 'Error en el servidor: ' + err.message });
  }
});

app.get('/api/user/balance/:userId', (req, res) => {
  const { userId } = req.params;
  const user = db.prepare('SELECT balance FROM users WHERE id = ?').get(userId);
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  res.json({ balance: user.balance });
});

app.post('/api/user/change-password', (req, res) => {
  try {
    const { userId, newPassword } = req.body;
    if (!newPassword || newPassword.trim().length < 4) {
      return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 4 caracteres.' });
    }
    const hashedPassword = bcrypt.hashSync(newPassword.trim(), 10);
    db.prepare('UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?').run(hashedPassword, userId);
    res.json({ message: 'Contraseña actualizada con éxito.' });
  } catch (err) {
    res.status(500).json({ error: 'Error al actualizar contraseña: ' + err.message });
  }
});

app.post('/api/admin/update-name', (req, res) => {
  try {
    const { adminId, newName } = req.body;
    const cleanName = (newName || '').trim();
    if (!cleanName) return res.status(400).json({ error: 'El nombre no puede estar vacío.' });

    db.prepare("UPDATE users SET name = ? WHERE id = ? AND role = 'admin'").run(cleanName, adminId);
    res.json({ message: 'Nombre de Administrador actualizado correctamente.', newName: cleanName });
  } catch (err) {
    res.status(500).json({ error: 'Error actualizando nombre: ' + err.message });
  }
});

app.post('/api/admin/reset-password', (req, res) => {
  try {
    const { userId, tempPassword } = req.body;
    if (!tempPassword || tempPassword.trim() === '') return res.status(400).json({ error: 'Ingresa una contraseña válida.' });

    const hashedPassword = bcrypt.hashSync(tempPassword.trim(), 10);
    const result = db.prepare('UPDATE users SET password = ?, must_change_password = 1 WHERE id = ?').run(hashedPassword, userId);
    if (result.changes === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

    res.json({ message: 'Contraseña del revendedor actualizada correctamente.' });
  } catch (err) {
    res.status(500).json({ error: 'Error al reiniciar contraseña: ' + err.message });
  }
});

app.post('/api/admin/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const cleanEmail = (email || '').trim().toLowerCase();
    if (!cleanEmail) return res.status(400).json({ error: 'Debes ingresar tu correo electrónico.' });

    const genericMsg = "Revisa tu bandeja de entrada o carpeta de spam.";
    
    const adminUser = db.prepare("SELECT * FROM users WHERE email = ? AND role = 'admin'").get(cleanEmail);
    if (!adminUser) return res.json({ message: genericMsg });

    const tempPassword = "RESET" + Math.floor(100000 + Math.random() * 900000);
    const hashedPassword = bcrypt.hashSync(tempPassword, 10);
    db.prepare('UPDATE users SET password = ?, must_change_password = 1 WHERE id = ?').run(hashedPassword, adminUser.id);

    sendAdminRecoveryEmail(cleanEmail, tempPassword);

    res.json({ message: genericMsg });
  } catch (err) {
    res.status(500).json({ error: 'Error al procesar recuperación: ' + err.message });
  }
});

// DASHBOARD
app.get('/api/reseller/dashboard/:userId', (req, res) => {
  const { userId } = req.params;
  const todayStr = new Date().toISOString().split('T')[0];

  const sales = db.prepare(`
    SELECT s.*, p.price as cost_price
    FROM stock s
    JOIN products p ON s.product_id = p.id
    WHERE s.assigned_to_user_id = ? AND s.status = 'sold'
  `).all(userId);

  let todaySalesCount = 0, todayCostTotal = 0, todayRevenueTotal = 0, totalProfit = 0;

  sales.forEach(s => {
    const sDate = (s.purchase_date || '').split('T')[0];
    const salePrice = s.reseller_sale_price || 0;
    const profit = salePrice > 0 ? (salePrice - s.cost_price) : 0;
    totalProfit += profit;

    if (sDate === todayStr) {
      todaySalesCount++;
      todayCostTotal += s.cost_price;
      todayRevenueTotal += salePrice;
    }
  });

  res.json({
    todaySalesCount,
    todayCostTotal,
    todayRevenueTotal,
    todayProfit: todayRevenueTotal > 0 ? (todayRevenueTotal - todayCostTotal) : 0,
    totalProfit,
    totalOrders: sales.length
  });
});

app.post('/api/reseller/set-sale-price', (req, res) => {
  const { stockId, salePrice } = req.body;
  const numPrice = parseFloat(salePrice);
  if (isNaN(numPrice) || numPrice < 0) return res.status(400).json({ error: 'Monto de venta inválido.' });

  db.prepare('UPDATE stock SET reseller_sale_price = ? WHERE id = ?').run(numPrice, stockId);
  res.json({ message: 'Precio de venta registrado correctamente.' });
});

app.get('/api/admin/sales-report', (req, res) => {
  const sales = db.prepare(`
    SELECT s.*, p.price as sale_amount, p.name as product_name, u.email as reseller_email
    FROM stock s
    JOIN products p ON s.product_id = p.id
    LEFT JOIN users u ON s.assigned_to_user_id = u.id
    WHERE s.status = 'sold'
    ORDER BY s.purchase_date DESC
  `).all();

  let totalAdminSalesAmount = 0, todayAmount = 0, weekAmount = 0, monthAmount = 0;
  const now = new Date();
  const todayStr = now.toISOString().split('T')[0];
  const startOfWeek = new Date(now);
  startOfWeek.setDate(now.getDate() - now.getDay());
  const startOfMonthStr = now.toISOString().slice(0, 7);
  const salesByDay = {};

  sales.forEach(s => {
    const amount = s.sale_amount || 0;
    totalAdminSalesAmount += amount;
    const dateObj = new Date(s.purchase_date || Date.now());
    const dateStr = dateObj.toISOString().split('T')[0];
    salesByDay[dateStr] = (salesByDay[dateStr] || 0) + amount;

    if (dateStr === todayStr) todayAmount += amount;
    if (dateObj >= startOfWeek) weekAmount += amount;
    if (dateStr.startsWith(startOfMonthStr)) monthAmount += amount;
  });

  res.json({ totalAdminSalesAmount, todayAmount, weekAmount, monthAmount, salesByDay, salesList: sales });
});

app.get('/api/admin/grouped-inventory', (req, res) => {
  const accounts = db.prepare(`
    SELECT platform_name, email_account, password_account,
      COUNT(id) as total_profiles,
      SUM(CASE WHEN status = 'available' THEN 1 ELSE 0 END) as available_profiles,
      SUM(CASE WHEN status = 'sold' THEN 1 ELSE 0 END) as sold_profiles
    FROM stock
    GROUP BY platform_name, email_account
    ORDER BY platform_name ASC, email_account ASC
  `).all();
  res.json(accounts);
});

app.get('/api/admin/metrics', (req, res) => {
  const resellerRanking = db.prepare(`
    SELECT u.id, u.name, u.email, u.balance, 
           COUNT(s.id) as total_purchases, 
           COALESCE(SUM(p.price), 0) as total_spent
    FROM users u
    LEFT JOIN stock s ON u.id = s.assigned_to_user_id AND s.status = 'sold'
    LEFT JOIN products p ON s.product_id = p.id
    WHERE u.role = 'reseller'
    GROUP BY u.id
    ORDER BY total_spent DESC
  `).all();

  const allStock = db.prepare(`
    SELECT s.*, p.name as product_name, p.type as product_type, u.email as assigned_user
    FROM stock s
    JOIN products p ON s.product_id = p.id
    LEFT JOIN users u ON s.assigned_to_user_id = u.id
    ORDER BY s.id DESC
  `).all();

  res.json({ resellerRanking, allStock });
});

app.post('/api/admin/manage-balance', (req, res) => {
  try {
    const { adminPassword, targetEmail, amount, action } = req.body;
    const numAmount = parseFloat(amount);
    const cleanTargetEmail = (targetEmail || '').trim().toLowerCase();

    const admin = db.prepare("SELECT * FROM users WHERE role = 'admin'").get();
    if (!admin || !bcrypt.compareSync(adminPassword, admin.password)) {
      return res.status(401).json({ error: 'Contraseña de Administrador incorrecta.' });
    }

    if (isNaN(numAmount) || numAmount <= 0) {
      return res.status(400).json({ error: 'Ingresa un monto válido mayor a 0.' });
    }

    const targetUser = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanTargetEmail);
    if (!targetUser) return res.status(404).json({ error: 'El usuario revendedor no fue encontrado.' });

    if (action === 'deduct') {
      if (targetUser.balance < numAmount) {
        return res.status(400).json({ error: `El usuario solo cuenta con $${targetUser.balance.toFixed(2)} MXN.` });
      }
      db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(numAmount, targetUser.id);
      return res.json({ message: `Se descontaron $${numAmount.toFixed(2)} MXN a ${cleanTargetEmail}` });
    } else {
      db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(numAmount, targetUser.id);
      return res.json({ message: `Se abonaron $${numAmount.toFixed(2)} MXN a ${cleanTargetEmail}` });
    }
  } catch (err) {
    res.status(500).json({ error: 'Error en el servidor: ' + err.message });
  }
});

app.post('/api/admin/delete-user', (req, res) => {
  try {
    const { adminPassword, userId } = req.body;
    const admin = db.prepare("SELECT * FROM users WHERE role = 'admin'").get();
    if (!admin || !bcrypt.compareSync(adminPassword, admin.password)) {
      return res.status(401).json({ error: 'Contraseña de Administrador incorrecta.' });
    }

    const targetUser = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!targetUser) return res.status(404).json({ error: 'El usuario no existe.' });
    if (targetUser.role === 'admin') return res.status(403).json({ error: 'No se permite eliminar al Administrador.' });

    const deleteTransaction = db.transaction(() => {
      db.prepare('UPDATE stock SET assigned_to_user_id = NULL WHERE assigned_to_user_id = ?').run(userId);
      db.prepare('DELETE FROM support_tickets WHERE user_id = ?').run(userId);
      db.prepare('DELETE FROM recharge_requests WHERE user_id = ?').run(userId);
      db.prepare('DELETE FROM users WHERE id = ?').run(userId);
    });
    deleteTransaction();

    res.json({ message: `El usuario ${targetUser.email} fue eliminado correctamente.` });
  } catch (err) {
    res.status(500).json({ error: 'Error al eliminar usuario: ' + err.message });
  }
});

// RECARGAS Y COMPROBANTES DE RESELLER
app.post('/api/reseller/recharge', upload.single('receiptImage'), (req, res) => {
  try {
    const { userId, amount } = req.body;
    const numAmount = parseFloat(amount);

    if (!userId || isNaN(parseInt(userId))) {
      return res.status(400).json({ error: 'ID de usuario no válido.' });
    }

    if (isNaN(numAmount) || numAmount <= 0) {
      return res.status(400).json({ error: 'Ingresa un monto válido mayor a $0.' });
    }

    const user = db.prepare('SELECT id FROM users WHERE id = ?').get(userId);
    if (!user) {
      return res.status(404).json({ error: 'El usuario no existe.' });
    }

    let receiptUrl = '';
    if (req.file) {
      receiptUrl = '/uploads/' + req.file.filename;
    }

    const isoNow = new Date().toISOString();

    db.prepare(`
      INSERT INTO recharge_requests (user_id, amount, receipt_url, status, created_at)
      VALUES (?, ?, ?, 'pending', ?)
    `).run(userId, numAmount, receiptUrl, isoNow);

    res.json({ message: '¡Solicitud de recarga enviada con éxito! El administrador la revisará en breve.' });
  } catch (err) {
    console.error("Error procesando recarga:", err);
    res.status(500).json({ error: 'Error enviando solicitud de recarga: ' + err.message });
  }
});

app.get('/api/admin/recharge-requests', (req, res) => {
  cleanupOldRechargeRequests();
  const requests = db.prepare(`
    SELECT r.*, u.name as user_name, u.email as user_email
    FROM recharge_requests r
    JOIN users u ON r.user_id = u.id
    ORDER BY r.created_at DESC
  `).all();
  res.json(requests);
});

app.post('/api/admin/recharge-requests/process', (req, res) => {
  try {
    const { adminPassword, requestId, action } = req.body;

    const admin = db.prepare("SELECT * FROM users WHERE role = 'admin'").get();
    if (!admin || !bcrypt.compareSync(adminPassword, admin.password)) {
      return res.status(401).json({ error: 'Contraseña de Administrador incorrecta. Autorización denegada.' });
    }

    const recharge = db.prepare('SELECT * FROM recharge_requests WHERE id = ?').get(requestId);

    if (!recharge || recharge.status !== 'pending') {
      return res.status(400).json({ error: 'La solicitud no está pendiente.' });
    }

    if (action === 'approve') {
      const processTx = db.transaction(() => {
        db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(recharge.amount, recharge.user_id);
        db.prepare("UPDATE recharge_requests SET status = 'approved' WHERE id = ?").run(requestId);
      });
      processTx();
      res.json({ message: `Recarga aprobada. Se han abonado $${recharge.amount.toFixed(2)} MXN al revendedor.` });
    } else {
      db.prepare("UPDATE recharge_requests SET status = 'rejected' WHERE id = ?").run(requestId);
      res.json({ message: 'Solicitud de recarga rechazada.' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Error procesando la solicitud: ' + err.message });
  }
});

// TICKETS Y SOPORTE
app.post('/api/support/tickets', upload.single('ticketImage'), (req, res) => {
  try {
    const { userId, orderId, subject, comment } = req.body;
    if (!subject || !comment) return res.status(400).json({ error: 'El asunto y el comentario son obligatorios.' });

    let imageUrl = '';
    if (req.file) imageUrl = '/uploads/' + req.file.filename;

    const isoDate = new Date().toISOString();

    db.prepare(`
      INSERT INTO support_tickets (user_id, order_id, subject, comment, image_url, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 'open', ?, ?)
    `).run(userId, orderId || null, subject.trim(), comment.trim(), imageUrl, isoDate, isoDate);

    res.json({ message: 'Ticket de soporte enviado correctamente.' });
  } catch (err) {
    res.status(500).json({ error: 'Error enviando el ticket: ' + err.message });
  }
});

app.get('/api/support/tickets', (req, res) => {
  const tickets = db.prepare(`
    SELECT t.*, u.name as user_name, u.email as user_email
    FROM support_tickets t
    JOIN users u ON t.user_id = u.id
    ORDER BY t.created_at DESC
  `).all();
  res.json(tickets);
});

app.get('/api/support/tickets/:userId', (req, res) => {
  const { userId } = req.params;
  const tickets = db.prepare(`
    SELECT t.*, u.name as user_name, u.email as user_email
    FROM support_tickets t
    JOIN users u ON t.user_id = u.id
    WHERE t.user_id = ?
    ORDER BY t.created_at DESC
  `).all(userId);
  res.json(tickets);
});

app.post('/api/admin/support/update-status', upload.single('adminTicketImage'), (req, res) => {
  try {
    const { ticketId, status, adminComment } = req.body;
    if (!ticketId || !status) return res.status(400).json({ error: 'ID de ticket y estado son requeridos.' });

    let adminImageUrl = null;
    if (req.file) adminImageUrl = '/uploads/' + req.file.filename;

    const isoNow = new Date().toISOString();

    if (adminImageUrl) {
      db.prepare(`
        UPDATE support_tickets 
        SET status = ?, admin_comment = ?, admin_image_url = ?, updated_at = ? 
        WHERE id = ?
      `).run(status, adminComment || '', adminImageUrl, isoNow, ticketId);
    } else {
      db.prepare(`
        UPDATE support_tickets 
        SET status = ?, admin_comment = COALESCE(?, admin_comment), updated_at = ? 
        WHERE id = ?
      `).run(status, adminComment || null, isoNow, ticketId);
    }

    res.json({ message: 'Estado del ticket actualizado.' });
  } catch (err) {
    res.status(500).json({ error: 'Error actualizando ticket: ' + err.message });
  }
});

app.delete('/api/admin/support/tickets/:id', (req, res) => {
  const { id } = req.params;
  try {
    const ticket = db.prepare('SELECT * FROM support_tickets WHERE id = ?').get(id);
    if (!ticket) return res.status(404).json({ error: 'Ticket no encontrado.' });

    if (ticket.image_url) {
      const fullPath = path.join(__dirname, ticket.image_url);
      if (fs.existsSync(fullPath)) {
        try { fs.unlinkSync(fullPath); } catch (e) {}
      }
    }

    if (ticket.admin_image_url) {
      const fullAdminPath = path.join(__dirname, ticket.admin_image_url);
      if (fs.existsSync(fullAdminPath)) {
        try { fs.unlinkSync(fullAdminPath); } catch (e) {}
      }
    }

    db.prepare('DELETE FROM support_tickets WHERE id = ?').run(id);
    res.json({ message: 'Ticket de soporte e imágenes eliminados correctamente.' });
  } catch (err) {
    res.status(500).json({ error: 'Error al eliminar ticket: ' + err.message });
  }
});

// ALERTAS DE SOPORTE
app.get('/api/support/alerts/admin', (req, res) => {
  cleanupOldRechargeRequests();
  const openTickets = db.prepare("SELECT COUNT(id) as count FROM support_tickets WHERE status = 'open'").get();
  const pendingRecharges = db.prepare("SELECT COUNT(id) as count FROM recharge_requests WHERE status = 'pending'").get();

  res.json({
    openCount: openTickets ? openTickets.count : 0,
    reviewCount: 0,
    pendingRechargesCount: pendingRecharges ? pendingRecharges.count : 0
  });
});

app.get('/api/support/alerts/:userId', (req, res) => {
  const { userId } = req.params;
  const activeTickets = db.prepare(`
    SELECT COUNT(id) as count 
    FROM support_tickets 
    WHERE user_id = ? AND status IN ('review', 'resolved')
  `).get(userId);

  const lastUpdated = db.prepare("SELECT MAX(updated_at) as last_time FROM support_tickets WHERE user_id = ?").get(userId);

  res.json({
    reviewCount: activeTickets ? activeTickets.count : 0,
    resolvedCount: 0,
    lastUpdatedTime: lastUpdated ? lastUpdated.last_time : null
  });
});

// CATÁLOGO Y COMPRAS
app.get('/api/products', (req, res) => {
  const products = db.prepare(`
    SELECT p.*, COUNT(s.id) as stock_count 
    FROM products p 
    LEFT JOIN stock s ON p.id = s.product_id AND s.status = 'available'
    GROUP BY p.id
  `).all();
  res.json(products);
});

app.post('/api/admin/products', upload.single('productImageFile'), (req, res) => {
  try {
    const { name, type, price, imageUrl } = req.body;
    if (!name || !price) return res.status(400).json({ error: 'Ingresa el nombre y el precio.' });

    let finalImageUrl = (imageUrl || '').trim();
    if (req.file) finalImageUrl = '/uploads/' + req.file.filename;

    db.prepare("INSERT INTO products (name, type, price, image_url) VALUES (?, ?, ?, ?)").run(
      name.trim(), type, parseFloat(price), finalImageUrl
    );

    res.json({ message: 'Producto creado exitosamente en el catálogo.' });
  } catch (err) {
    res.status(500).json({ error: 'Error al registrar producto: ' + err.message });
  }
});

app.put('/api/admin/products/:id', upload.single('productImageFile'), (req, res) => {
  try {
    const { id } = req.params;
    const { name, type, price, imageUrl } = req.body;

    const existing = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
    if (!existing) return res.status(404).json({ error: 'Producto no encontrado.' });

    let finalImageUrl = existing.image_url;

    if (req.file) {
      finalImageUrl = '/uploads/' + req.file.filename;
    } else if (imageUrl !== undefined && imageUrl.trim() !== '') {
      finalImageUrl = imageUrl.trim();
    }

    const newName = name ? name.trim() : existing.name;
    const newType = type || existing.type;
    const newPrice = price !== undefined ? parseFloat(price) : existing.price;

    db.prepare(`
      UPDATE products 
      SET name = ?, type = ?, price = ?, image_url = ? 
      WHERE id = ?
    `).run(newName, newType, newPrice, finalImageUrl, id);

    res.json({ message: 'Producto actualizado correctamente.' });
  } catch (err) {
    res.status(500).json({ error: 'Error actualizando producto: ' + err.message });
  }
});

app.post('/api/buy-cart', (req, res) => {
  try {
    const { userId, cartItems } = req.body;
    if (!cartItems || !Array.isArray(cartItems) || cartItems.length === 0) {
      return res.status(400).json({ error: 'El carrito está vacío.' });
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });

    let totalCost = 0;
    const processList = [];

    for (const item of cartItems) {
      const product = db.prepare('SELECT * FROM products WHERE id = ?').get(item.productId);
      if (!product) return res.status(400).json({ error: `Producto no encontrado.` });

      const availableStock = db.prepare(`
        SELECT * FROM stock 
        WHERE product_id = ? AND status = 'available' 
        ORDER BY id ASC 
        LIMIT ?
      `).all(item.productId, item.quantity);

      if (availableStock.length < item.quantity) {
        return res.status(400).json({ error: `Stock insuficiente para ${product.name}.` });
      }

      totalCost += product.price * item.quantity;
      processList.push({ product, itemsToBuy: availableStock });
    }

    if (user.balance < totalCost) return res.status(400).json({ error: `Saldo insuficiente.` });

    const purchaseDate = new Date().toISOString();
    const processPurchase = db.transaction(() => {
      db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(totalCost, userId);
      for (const group of processList) {
        for (const stockItem of group.itemsToBuy) {
          db.prepare(`
            UPDATE stock 
            SET status = 'sold', assigned_to_user_id = ?, purchase_date = ? 
            WHERE id = ?
          `).run(userId, purchaseDate, stockItem.id);
        }
      }
    });

    processPurchase();

    res.json({ message: '¡Compra completada con éxito!', newBalance: user.balance - totalCost });
  } catch (err) {
    res.status(500).json({ error: 'Error procesando la compra: ' + err.message });
  }
});

app.get('/api/user/orders/:userId', (req, res) => {
  const { userId } = req.params;
  const orders = db.prepare(`
    SELECT s.*, p.name as product_name, p.type as product_type, p.price as cost_price
    FROM stock s
    JOIN products p ON s.product_id = p.id
    WHERE s.assigned_to_user_id = ? AND s.status = 'sold'
    ORDER BY s.purchase_date DESC
  `).all(userId);

  const now = new Date();

  function formatDate(d) {
    const day = String(d.getDate()).padStart(2, '0');
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const year = d.getFullYear();
    return `${day}/${month}/${year}`;
  }

  const result = orders.map(o => {
    const pDate = new Date(o.purchase_date || Date.now());
    const expDate = new Date(pDate.getTime() + (30 * 24 * 60 * 60 * 1000));
    const diffTime = expDate - now;
    const daysLeft = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    let comboParsed = null;
    if (o.combo_data) {
      try { comboParsed = JSON.parse(o.combo_data); } catch(e){}
    }

    return {
      ...o,
      purchase_date_formatted: formatDate(pDate),
      expiration_date_formatted: formatDate(expDate),
      days_left: daysLeft > 0 ? daysLeft : 0,
      is_near_expiration: daysLeft <= 3,
      combo_parsed: comboParsed
    };
  });

  res.json(result);
});

app.get('/api/admin/users', (req, res) => {
  const users = db.prepare('SELECT id, name, email, role, balance, must_change_password FROM users').all();
  res.json(users);
});

app.post('/api/admin/users', (req, res) => {
  const { name, email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Debes ingresar correo y contraseña.' });

  try {
    const cleanEmail = email.trim().toLowerCase();
    const cleanName = (name || 'Revendedor').trim();

    const existing = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail);
    if (existing) return res.status(400).json({ error: 'El correo ya está registrado.' });

    const hashedPassword = bcrypt.hashSync(password, 10);
    db.prepare("INSERT INTO users (name, email, password, role, balance, must_change_password) VALUES (?, ?, ?, 'reseller', 0.0, 1)").run(cleanName, cleanEmail, hashedPassword);
    res.json({ message: 'Revendedor registrado con éxito.' });
  } catch (err) {
    res.status(500).json({ error: 'Error en la base de datos: ' + err.message });
  }
});

app.delete('/api/admin/products/:id', (req, res) => {
  const { id } = req.params;
  try {
    const deleteTransaction = db.transaction(() => {
      db.prepare("UPDATE stock SET product_id = NULL WHERE product_id = ? AND status = 'sold'").run(id);
      db.prepare("DELETE FROM stock WHERE product_id = ? AND status = 'available'").run(id);
      db.prepare("DELETE FROM products WHERE id = ?").run(id);
    });
    deleteTransaction();
    res.json({ message: 'Producto eliminado del catálogo correctamente.' });
  } catch (err) {
    res.status(500).json({ error: 'Error al eliminar producto: ' + err.message });
  }
});

// CARGA DE STOCK CON DESCUENTO MULTI-CUENTA
app.post('/api/admin/stock/bulk', (req, res) => {
  const { productId, isCombo, masterAccountIds, items } = req.body;
  if (!productId || !items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Completa todos los datos de los perfiles.' });
  }

  try {
    if (isCombo) {
      const comboJson = JSON.stringify(items);
      const mainItem = items[0] || {};
      const uniqueCode = generateUnique8Code();

      db.prepare(`
        INSERT INTO stock (unique_code, product_id, platform_name, email_account, password_account, profile_name, combo_data, status) 
        VALUES (?, ?, 'Paquete Combo/Dúo', ?, ?, ?, ?, 'available')
      `).run(uniqueCode, parseInt(productId), mainItem.email || 'Combo Multi-Cuenta', mainItem.password || 'Varias', 'Acceso Completo', comboJson);

      // Descuenta cada perfil utilizado en los combos
      if (Array.isArray(masterAccountIds) && masterAccountIds.length > 0) {
        masterAccountIds.forEach(mId => {
          db.prepare(`
            UPDATE master_inventory 
            SET used_profiles = used_profiles + 1 
            WHERE id = ?
          `).run(mId);

          const mAcc = db.prepare("SELECT * FROM master_inventory WHERE id = ?").get(mId);
          if (mAcc && mAcc.used_profiles >= mAcc.total_profiles) {
            db.prepare("UPDATE master_inventory SET status = 'exhausted' WHERE id = ?").run(mId);
          }
        });
      }

      res.json({ message: '¡Éxito! Paquete Combo/Dúo cargado al inventario.' });
    } else {
      const insertStmt = db.prepare(`
        INSERT INTO stock (unique_code, product_id, platform_name, email_account, password_account, profile_name, status) 
        VALUES (?, ?, ?, ?, ?, ?, 'available')
      `);

      let addedCount = 0;
      const bulkInsert = db.transaction((rows) => {
        for (const item of rows) {
          if (item.email && item.password && item.profile) {
            const uniqueCode = generateUnique8Code();
            insertStmt.run(uniqueCode, parseInt(productId), item.platform || '', item.email.trim(), item.password.trim(), item.profile.trim());
            addedCount++;
          }
        }

        if (Array.isArray(masterAccountIds) && masterAccountIds.length > 0) {
          const mId = masterAccountIds[0];
          db.prepare(`
            UPDATE master_inventory 
            SET used_profiles = used_profiles + ? 
            WHERE id = ?
          `).run(addedCount, mId);

          const mAcc = db.prepare("SELECT * FROM master_inventory WHERE id = ?").get(mId);
          if (mAcc && mAcc.used_profiles >= mAcc.total_profiles) {
            db.prepare("UPDATE master_inventory SET status = 'exhausted' WHERE id = ?").run(mId);
          }
        }
      });

      bulkInsert(items);
      res.json({ message: `¡Éxito! Se agregaron ${items.length} unidades/perfiles al inventario.` });
    }
  } catch (err) {
    res.status(500).json({ error: 'Error al guardar el stock: ' + err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Cpanel Anubis activo en puerto ${PORT}`));
