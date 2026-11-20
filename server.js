require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const mysql = require('mysql2/promise');
const cloudinary = require('cloudinary').v2;

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'gala_super_secret_key_2026';

// ============================================================
// CLOUDINARY CONFIG
// ============================================================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ============================================================
// UPLOADS LOCALES (capturas Yape)
// ⚠️ En Render el disco es efímero: esto se borra en cada deploy.
//    Para producción real, migra a Cloudinary o S3.
// ============================================================
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
app.use('/uploads', express.static(uploadsDir));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `yape-${Date.now()}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) return cb(new Error('Solo imágenes'));
    cb(null, true);
  }
});

// ============================================================
// MYSQL POOL (con SSL obligatorio para Aiven)
// ============================================================
const caCertPath = path.join(__dirname, 'ca.pem');
let caCert;
try {
  caCert = fs.readFileSync(caCertPath, 'utf8');
  console.log('[DB] CA Certificate cargado desde ca.pem');
} catch (err) {
  console.warn('[DB] ADVERTENCIA: no se encontró ca.pem. La conexión a Aiven fallará si exige SSL.');
}

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'gala_db',
  waitForConnections: true,
  connectionLimit: 10,
  charset: 'utf8mb4',
  ssl: caCert ? { ca: caCert, rejectUnauthorized: true } : undefined,
});

// ============================================================
// INICIALIZAR TABLAS
// ============================================================
async function initDatabase() {
  // En Aiven, la base de datos ya existe (defaultdb). No intentamos CREATEdb.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(120) NOT NULL,
      email VARCHAR(120) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      role ENUM('admin','user') NOT NULL DEFAULT 'user',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS payments (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      user_name VARCHAR(120) NOT NULL,
      stage VARCHAR(60) NOT NULL,
      amount DECIMAL(6,2) NOT NULL DEFAULT 1.00,
      operation_code VARCHAR(30) NOT NULL,
      screenshot VARCHAR(255),
      status ENUM('pendiente','aprobado') NOT NULL DEFAULT 'pendiente',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS stage_videos (
      id INT AUTO_INCREMENT PRIMARY KEY,
      stage VARCHAR(60) NOT NULL,
      title VARCHAR(150) NOT NULL,
      cloudinary_public_id VARCHAR(255) NOT NULL,
      cloudinary_url VARCHAR(500) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Crear usuarios semilla solo si la tabla está vacía
  const [rows] = await pool.query('SELECT COUNT(*) AS count FROM users');
  if (rows[0].count === 0) {
    const adminPass = bcrypt.hashSync('password123', 8);
    const userPass = bcrypt.hashSync('password123', 8);
    await pool.query(
      'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
      ['VICTOR GABRIEL PINEDO RIOJA', 'victor@galacubos.com', adminPass, 'admin']
    );
    await pool.query(
      'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
      ['Alumno GALA', 'alumno@galacubos.com', userPass, 'user']
    );
    console.log('Usuarios semilla creados.');
  }

  console.log('Base de datos lista.');
}

// ============================================================
// MIDDLEWARES
// ============================================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Token no proporcionado' });
  }
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Token inválido o expirado' });
    }
    req.user = user;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Acceso denegado. Se requiere rol admin.' });
  }
  next();
};

// ============================================================
// HEALTH CHECK (útil para Render)
// ============================================================
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============================================================
// AUTH
// ============================================================
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      return res.status(401).json({ message: 'Credenciales incorrectas' });
    }
    const user = rows[0];
    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ message: 'Credenciales incorrectas' });
    }
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: '2h' }
    );
    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error de servidor' });
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Todos los campos son obligatorios' });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: 'Mínimo 6 caracteres' });
    }
    const [exists] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (exists.length > 0) {
      return res.status(409).json({ message: 'El correo ya está registrado' });
    }
    const hash = bcrypt.hashSync(password, 8);
    const [result] = await pool.query(
      'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
      [name, email, hash, 'user']
    );
    const newUser = { id: result.insertId, name, email, role: 'user' };
    const token = jwt.sign(newUser, JWT_SECRET, { expiresIn: '2h' });
    res.status(201).json({ token, user: newUser });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error de servidor' });
  }
});

// ============================================================
// PAGOS
// ============================================================
app.post('/api/payments', authenticateToken, upload.single('screenshot'), async (req, res) => {
  try {
    const { stage, amount, operationCode } = req.body;
    if (!stage || !operationCode) {
      return res.status(400).json({ message: 'Faltan datos' });
    }
    const screenshotUrl = req.file ? `/uploads/${req.file.filename}` : null;
    const [result] = await pool.query(
      `INSERT INTO payments (user_id, user_name, stage, amount, operation_code, screenshot, status)
       VALUES (?, ?, ?, ?, ?, ?, 'pendiente')`,
      [req.user.id, req.user.name, stage, amount || 1, operationCode, screenshotUrl]
    );
    res.status(201).json({
      id: result.insertId,
      stage, amount, operationCode, screenshot: screenshotUrl, status: 'pendiente'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al registrar pago' });
  }
});

app.get('/api/payments/my-payments', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM payments WHERE user_id = ? ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(rows.map(mapPayment));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al obtener pagos' });
  }
});

// ============================================================
// ADMIN: PAGOS
// ============================================================
app.get('/api/admin/payments', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM payments ORDER BY created_at DESC');
    res.json(rows.map(mapPayment));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al obtener pagos del admin' });
  }
});

app.put('/api/admin/payments/:id/approve', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const numericId = String(id).replace(/\D/g, '');
    if (!numericId) return res.status(400).json({ message: 'ID inválido' });
    const [result] = await pool.query(
      "UPDATE payments SET status = 'aprobado' WHERE id = ?",
      [numericId]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Pago no encontrado' });
    }
    res.json({ message: 'Pago aprobado' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al aprobar pago' });
  }
});

// ============================================================
// ADMIN: CLOUDINARY (firma de subida)
// ============================================================
app.post('/api/admin/sign-upload', authenticateToken, isAdmin, (req, res) => {
  try {
    const folder = (req.body.folder || 'gala/videos').trim();
    const timestamp = Math.round(Date.now() / 1000);
    const paramsToSign = { timestamp, folder };
    const signature = cloudinary.utils.api_sign_request(
      paramsToSign,
      process.env.CLOUDINARY_API_SECRET
    );
    res.json({
      signature,
      timestamp,
      folder,
      api_key: process.env.CLOUDINARY_API_KEY,
      cloud_name: process.env.CLOUDINARY_CLOUD_NAME
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al firmar' });
  }
});

// ============================================================
// ADMIN: VÍDEOS
// ============================================================
app.post('/api/admin/stage-videos', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { stage, title, publicId, url } = req.body;
    if (!stage || !title || !publicId || !url) {
      return res.status(400).json({ message: 'Faltan datos' });
    }
    const [result] = await pool.query(
      'INSERT INTO stage_videos (stage, title, cloudinary_public_id, cloudinary_url) VALUES (?, ?, ?, ?)',
      [stage.trim(), title.trim(), publicId, url]
    );
    res.status(201).json({ id: result.insertId, stage, title, url, publicId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al guardar vídeo' });
  }
});

app.delete('/api/admin/stage-videos/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const numericId = parseInt(req.params.id, 10);
    if (isNaN(numericId)) return res.status(400).json({ message: 'ID inválido' });

    const [rows] = await pool.query('SELECT * FROM stage_videos WHERE id = ?', [numericId]);
    if (rows.length === 0) return res.status(404).json({ message: 'Vídeo no encontrado' });

    const publicId = rows[0].cloudinary_public_id;
    try {
      await cloudinary.uploader.destroy(publicId, { resource_type: 'video' });
    } catch (cloudErr) {
      console.error('[Cloudinary] Error al eliminar (continúo):', cloudErr);
    }
    await pool.query('DELETE FROM stage_videos WHERE id = ?', [numericId]);
    res.json({ message: 'Vídeo eliminado' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al eliminar' });
  }
});

// ============================================================
// USUARIO: listar vídeos de una etapa (con LOWER/TRIM para evitar mismatch)
// ============================================================
app.get('/api/stage-videos/:stage', authenticateToken, async (req, res) => {
  try {
    const stageParam = decodeURIComponent(req.params.stage).trim();

    if (req.user.role !== 'admin') {
      const [payments] = await pool.query(
        `SELECT id FROM payments
         WHERE user_id = ? AND LOWER(TRIM(stage)) = LOWER(TRIM(?)) AND status = 'aprobado'`,
        [req.user.id, stageParam]
      );
      if (payments.length === 0) {
        return res.status(403).json({ message: 'No tienes acceso a esta etapa' });
      }
    }

    const [videos] = await pool.query(
      `SELECT * FROM stage_videos
       WHERE LOWER(TRIM(stage)) = LOWER(TRIM(?))
       ORDER BY created_at DESC`,
      [stageParam]
    );

    res.json(videos.map(v => ({
      id: v.id,
      stage: v.stage,
      title: v.title,
      url: v.cloudinary_url,
      publicId: v.cloudinary_public_id
    })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al obtener vídeos' });
  }
});

// ============================================================
// MAPEO
// ============================================================
function mapPayment(row) {
  return {
    id: `YAPE-${row.id.toString().padStart(3, '0')}`,
    userId: row.user_id,
    userName: row.user_name,
    stage: row.stage,
    amount: Number(row.amount),
    date: new Date(row.created_at).toLocaleDateString(),
    status: row.status,
    operationCode: row.operation_code,
    screenshot: row.screenshot
  };
}

// ============================================================
// START
// ============================================================
const PORT = process.env.PORT || 3000;

initDatabase()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Backend GALA escuchando en el puerto ${PORT}`);
    });
  })
  .catch(err => {
    console.error('Error al iniciar BD:', err);
    process.exit(1);
  });