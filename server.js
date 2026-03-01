const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
require('dotenv').config();

const app = express();
// Configurar "trust proxy" porque el servidor está detrás de Coolify/Nginx/Cloudflare
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;

// Configuración de logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'biometrico-api' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Crear directorio de logs si no existe
if (!fs.existsSync('logs')) {
  fs.mkdirSync('logs');
}

// Configuración de base de datos
const DB_TYPE = process.env.DB_TYPE || 'sqlite'; // Forzar sqlite por defecto si no se especifica

// Inicialización de base de datos
let db;

if (DB_TYPE === 'sqlite') {
  const dbPath = process.env.DB_FILE || path.join(__dirname, 'biometrico_nube.db');
  db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
      console.error('❌ Error abriendo base de datos SQLite:', err.message);
    } else {
      console.log(`✅ Conectado a SQLite: ${dbPath}`);
      // Habilitar modo WAL para mejor rendimiento en escrituras concurrentes
      db.run('PRAGMA journal_mode = WAL');
      db.run('PRAGMA synchronous = NORMAL');
      initializeDatabase();
    }
  });
} else {
  // Configuración PostgreSQL (opcional)
  // ... código postgres ...
}

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  credentials: true
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // límite de 100 solicitudes por IP
  message: 'Too many requests from this IP'
});
app.use('/api/', limiter);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Middleware de logging
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path} - ${req.ip}`);
  next();
});

// Validación de API Key
const validateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || req.body.api_key;

  if (!apiKey) {
    return res.status(401).json({
      success: false,
      error: 'API Key requerida'
    });
  }

  if (apiKey !== process.env.API_KEY) {
    logger.warn(`API Key inválida desde IP: ${req.ip}`);
    return res.status(401).json({
      success: false,
      error: 'API Key inválida'
    });
  }

  next();
};

// Inicialización de tablas
// Inicialización de tablas
async function initializeDatabase() {
  try {
    // Tabla de dispositivos
    await runRun(`
      CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        name TEXT,
        location TEXT,
        last_seen DATETIME,
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabla de usuarios
    await runRun(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT UNIQUE NOT NULL,
        uid INTEGER NOT NULL,
        name TEXT,
        privilege INTEGER DEFAULT 0,
        email TEXT,
        phone TEXT,
        department TEXT,
        active INTEGER DEFAULT 1,
        device_ip TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabla de asistencia
    await runRun(`
      CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        timestamp DATETIME NOT NULL,
        punch INTEGER DEFAULT 0,
        status INTEGER DEFAULT 0,
        device_ip TEXT NOT NULL,
        sync_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        processed INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, timestamp, device_ip)
      )
    `);

    // Tabla de logs de sincronización
    await runRun(`
      CREATE TABLE IF NOT EXISTS sync_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_ip TEXT NOT NULL,
        sync_type TEXT NOT NULL,
        records_count INTEGER DEFAULT 0,
        status TEXT NOT NULL,
        error_message TEXT,
        start_time DATETIME,
        end_time DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabla de notificaciones
    await runRun(`
      CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        message TEXT NOT NULL,
        user_id TEXT,
        device_ip TEXT,
        read INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Índices para mejor rendimiento
    await runRun('CREATE INDEX IF NOT EXISTS idx_attendance_user_timestamp ON attendance(user_id, timestamp)');
    await runRun('CREATE INDEX IF NOT EXISTS idx_attendance_device_timestamp ON attendance(device_ip, timestamp)');
    await runRun('CREATE INDEX IF NOT EXISTS idx_users_device_ip ON users(device_ip)');
    await runRun('CREATE INDEX IF NOT EXISTS idx_sync_logs_device ON sync_logs(device_ip)');

    logger.info('✅ Base de datos inicializada correctamente');
  } catch (error) {
    logger.error('❌ Error inicializando base de datos:', error);
    process.exit(1);
  }
}

// Función helper para ejecutar queries
function runQuery(query, params = []) {
  return new Promise((resolve, reject) => {
    db.all(query, params, (err, rows) => {
      if (err) {
        reject(err);
      } else {
        resolve(rows);
      }
    });
  });
}

// Helper para queries de ejecución (INSERT, UPDATE, DELETE)
function runRun(query, params = []) {
  return new Promise((resolve, reject) => {
    db.run(query, params, function (err) {
      if (err) {
        reject(err);
      } else {
        resolve(this);
      }
    });
  });
}

// API Endpoints

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'API funcionando correctamente',
    timestamp: new Date().toISOString(),
    version: '1.0.1',
    database: DB_TYPE
  });
});

// Webhook para recibir mensajes entrantes de Evolution (WhatsApp)
app.post('/api/whatsapp/incoming', async (req, res) => {
  try {
    // Si viene de Evolution, viene envuelto en req.body.data
    const eventData = req.body.data || req.body;

    logger.info(`Webhook INCOMING: ${JSON.stringify(eventData)}`);

    // Evitar que el bot se responda a sí mismo
    if (eventData.key && eventData.key.fromMe) {
      return res.json({ success: true, message: 'Ignorado (mensaje propio)' });
    }

    // Calcular fecha exacta de HOY en Perú (YYYY-MM-DD) restando 5 horas al UTC
    // Método a prueba de fallos absolutos sin depender de tzdata o Node Intl
    const limaTimeMs = Date.now() - (5 * 60 * 60 * 1000);
    const todayDateStr = new Date(limaTimeMs).toISOString().split('T')[0];

    // Extraer número (suele venir como 51948902026@s.whatsapp.net o con otros sufijos)
    let rawNumber = eventData.key?.remoteJid || eventData.number || '';
    let number = rawNumber.split('@')[0].replace(/\D/g, '');

    // Extraer texto (puede venir en varios formatos dependiendo si es texto plano o extendido)
    let incomingText = '';
    if (eventData.message?.conversation) {
      incomingText = eventData.message.conversation.trim();
    } else if (eventData.message?.extendedTextMessage?.text) {
      incomingText = eventData.message.extendedTextMessage.text.trim();
    } else if (eventData.textMessage && eventData.textMessage.text) {
      incomingText = eventData.textMessage.text.trim();
    }

    if (!number || !incomingText) {
      return res.json({ success: true, message: 'Ignorado (sin texto o número reconocible)' });
    }

    // Lógica para el Administrador
    if (number === '51948902026') {
      // Verificar si envió un código de empleado (asumimos numérico)
      const empCode = incomingText.trim();
      if (!empCode || isNaN(empCode)) {
        const adminHelp = `👋 Hola Administrador. Para ver las marcaciones de hoy de un empleado, envíame su código (ejemplo: "108").`;
        await sendWhatsAppMessage(number, adminHelp);
        return res.json({ success: true, message: 'Ayuda admin enviada' });
      }

      // Buscar al empleado por su ID
      const targetUserRows = await runQuery('SELECT user_id, name FROM users WHERE user_id = ?', [empCode]);
      if (!targetUserRows.length) {
        await sendWhatsAppMessage(number, `❌ No encontré ningún empleado con el código: ${empCode}`);
        return res.json({ success: true, message: 'Empleado no encontrado' });
      }

      const targetId = targetUserRows[0].user_id;
      const targetName = targetUserRows[0].name || targetId;

      // Obtener marcaciones del empleado
      const targetTodayRows = await runQuery(`
        SELECT timestamp, punch FROM attendance
        WHERE user_id = ? AND substr(timestamp, 1, 10) = ?
        ORDER BY timestamp ASC
      `, [targetId, todayDateStr]);

      if (!targetTodayRows.length) {
        await sendWhatsAppMessage(number, `👤 ${targetName} no tiene marcaciones registradas hoy.`);
        return res.json({ success: true, message: 'Sin marcaciones enviadas al admin' });
      }

      let adminSummary = `👤 Marcaciones de *${targetName}* hoy:\n`;
      targetTodayRows.forEach(r => {
        const type = r.punch === 0 ? 'Entrada' : (r.punch === 1 ? 'Salida' : 'Marcación');
        // El timestamp ya viene en hora de Lima desde la BD (ej. '2026-02-28 08:23:49')
        // Al armar el string, lo forzamos a interpretarse y mostrarse tal cual, sin shift de zona
        const safeTimeStr = r.timestamp.replace(' ', 'T');
        const d = new Date(safeTimeStr);
        let timeStr = r.timestamp.split(' ')[1] || r.timestamp; // Fallback al texto crudo
        if(!isNaN(d.getTime())) {
             timeStr = d.toLocaleTimeString('es-PE', { hour12: true, hour: '2-digit', minute: '2-digit' });
        }
        adminSummary += `- ${type}: ${timeStr}\n`;
      });

      await sendWhatsAppMessage(number, adminSummary.trim());
      return res.json({ success: true, message: 'Resumen admin enviado' });
    }

    // Lógica para Empleados normales
    // Buscar usuario por teléfono
    const userRows = await runQuery('SELECT user_id, name FROM users WHERE phone = ?', [number]);
    if (!userRows.length) {
      logger.warn(`WhatsApp inbound: número no registrado ${number}`);
      return res.json({ success: false, error: 'Número no registrado' });
    }
    const userId = userRows[0].user_id;
    const userName = userRows[0].name || userId;

    if (incomingText === '4') {
      // Obtener marcaciones del día para este usuario
      const todayRows = await runQuery(`
        SELECT timestamp, punch FROM attendance
        WHERE user_id = ? AND substr(timestamp, 1, 10) = ?
        ORDER BY timestamp ASC
      `, [userId, todayDateStr]);
      if (!todayRows.length) {
        const msg = `👋 Hola ${userName}, no tienes marcaciones registradas hoy.`;
        await sendWhatsAppMessage(number, msg);
        return res.json({ success: true, message: 'Sin marcaciones enviadas' });
      }
      let summary = `👋 Hola ${userName}, tus marcaciones de hoy:\n`;
      todayRows.forEach(r => {
        const type = r.punch === 0 ? 'Entrada' : (r.punch === 1 ? 'Salida' : 'Marcación');
        const safeTimeStr = r.timestamp.replace(' ', 'T');
        const d = new Date(safeTimeStr);
        let timeStr = r.timestamp.split(' ')[1] || r.timestamp;
        if(!isNaN(d.getTime())) {
             timeStr = d.toLocaleTimeString('es-PE', { hour12: true, hour: '2-digit', minute: '2-digit' });
        }
        summary += `- ${type}: ${timeStr}\n`;
      });
      await sendWhatsAppMessage(number, summary.trim());
      return res.json({ success: true, message: 'Resumen enviado' });
    } else {
      const msg = `👋 Hola ${userName}, para ver tus marcaciones de hoy escribe "4".`;
      await sendWhatsAppMessage(number, msg);
      return res.json({ success: true, message: 'Instrucción enviada' });
    }
  } catch (error) {
    logger.error('Error webhook WhatsApp inbound', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Helper para enviar mensaje de WhatsApp via Evolution API
function sendWhatsAppMessage(phone, text) {
  return new Promise((resolve, reject) => {
    try {
      if (!process.env.EVOLUTION_API_URL || !process.env.EVOLUTION_API_KEY || !process.env.EVOLUTION_INSTANCE) {
        logger.warn('🚫 Evolution API no configurado en .env. Omitiendo WhatsApp.');
        return resolve(false);
      }

      const payload = JSON.stringify({
        number: phone,
        text: text
      });

      const urlStr = `${process.env.EVOLUTION_API_URL}/message/sendText/${process.env.EVOLUTION_INSTANCE}`;
      const url = new URL(urlStr);

      const options = {
        hostname: url.hostname,
        port: url.port ? url.port : (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': process.env.EVOLUTION_API_KEY,
          'Content-Length': Buffer.byteLength(payload)
        }
      };

      const reqMethod = url.protocol === 'https:' ? https.request : http.request;

      const req = reqMethod(options, (res) => {
        let responseBody = '';
        res.on('data', (chunk) => responseBody += chunk);
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            logger.info(`✅ WhatsApp enviado a ${phone}`);
            resolve(true);
          } else {
            logger.warn(`⚠️ Error Evolution API (${res.statusCode}): ${responseBody}`);
            resolve(false);
          }
        });
      });

      req.on('error', (error) => {
        logger.error(`❌ Error conectando a Evolution API:`, error);
        resolve(false);
      });

      req.write(payload);
      req.end();
    } catch (e) {
      logger.error('Error en sendWhatsAppMessage:', e);
      resolve(false);
    }
  });
}

// Endpoint para actualizar teléfono de usuario
app.post('/api/users/update_phone', validateApiKey, async (req, res) => {
  try {
    const { user_id, phone } = req.body;
    await runRun('UPDATE users SET phone = ? WHERE user_id = ?', [phone, user_id]);
    res.json({ success: true, message: `Teléfono actualizado para ${user_id}` });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Endpoint para actualizar teléfono de usuario (ya creado anteriormente)\n\n// Endpoint principal de sincronización
app.post('/api/biometrico/sync', validateApiKey, async (req, res) => {
  const startTime = new Date();

  try {
    const { users, attendance, device_info } = req.body;

    if (!device_info || !device_info.ip) {
      return res.status(400).json({
        success: false,
        error: 'Información del dispositivo requerida'
      });
    }

    // Actualizar información del dispositivo
    await runRun(`
            INSERT OR REPLACE INTO devices (ip, name, last_seen, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        `, [device_info.ip, device_info.name || 'Dispositivo ZKTeco', startTime.toISOString()]);

    let usersInserted = 0;
    let attendanceInserted = 0;

    // Almacenar mensajes para enviarlos "en el fondo" después de responder
    const pendingWhatsAppMessages = [];

    // Iniciar transacción para procesamiento masivo
    await runRun('BEGIN TRANSACTION');

    // Procesar usuarios
    if (users && users.length > 0) {
      for (const user of users) {
        try {
          await runRun(`
                        INSERT INTO users (user_id, uid, name, privilege, device_ip, updated_at)
                        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        ON CONFLICT(user_id) DO UPDATE SET 
                            name=excluded.name, 
                            privilege=excluded.privilege, 
                            device_ip=excluded.device_ip, 
                            updated_at=CURRENT_TIMESTAMP
                    `, [user.user_id, user.uid, user.name, user.privilege, device_info.ip]);
          usersInserted++;
        } catch (error) {
          logger.warn(`Error procesando usuario ${user.user_id}:`, error.message);
        }
      }
    }

    // Procesar registros de asistencia
    if (attendance && attendance.length > 0) {
      for (const record of attendance) {
        try {
          // Usar INSERT OR IGNORE para evitar el SELECT previo y aprovechar el indice UNIQUE
          const result = await runRun(`
                INSERT OR IGNORE INTO attendance (user_id, timestamp, punch, status, device_ip)
                VALUES (?, ?, ?, ?, ?)
            `, [
            record.user_id,
            record.timestamp,
            record.punch,
            record.status,
            record.device_ip
          ]);

          // Si hubo cambios (filas insertadas > 0), procesar notificación
          if (result.changes > 0) {
            attendanceInserted++;

            // Buscar datos del usuario para el mensaje (esto es rápido por índice)
            const userRow = await runQuery(`SELECT name, phone FROM users WHERE user_id = ?`, [record.user_id]);
            const userName = (userRow && userRow.length > 0 && userRow[0].name) ? userRow[0].name : record.user_id;

            // Determinar tipo de marcación
            const punchType = record.punch === 0 ? 'Entrada' : (record.punch === 1 ? 'Salida' : 'Marcación');
            // Arreglar zona horaria
            const safeTimeStr = record.timestamp.includes('T') ? record.timestamp : record.timestamp.replace(' ', 'T') + '-05:00';
            const fechaObj = new Date(safeTimeStr);
            const fechaHora = isNaN(fechaObj.getTime()) ? record.timestamp : fechaObj.toLocaleString('es-PE', { timeZone: 'America/Lima', hour12: true, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).replace(',', '');

            // Solo enviar notificaciones de WhatsApp si el registro es de HOY (Lima)
            const recordDateStr = record.timestamp.split(' ')[0];
            const limaTimeMs = Date.now() - (5 * 60 * 60 * 1000);
            const todayDateStr = new Date(limaTimeMs).toISOString().split('T')[0];

            if (recordDateStr === todayDateStr) {
              const mensaje = `👋 ¡Hola ${userName}! Tu registro de *${punchType}* ha sido procesado exitosamente a las ${fechaHora}.`;
              const adminPhone = process.env.WHATSAPP_TEST_NUMBER;
              const employeePhone = (userRow && userRow.length > 0) ? userRow[0].phone : null;

              if (adminPhone) {
                pendingWhatsAppMessages.push({ phone: adminPhone, text: mensaje });
              }
              if (employeePhone && employeePhone !== adminPhone) {
                pendingWhatsAppMessages.push({ phone: employeePhone, text: mensaje });
              }
            }
          }
        } catch (error) {
          logger.warn(`Error procesando asistencia ${record.user_id}:`, error.message);
        }
      }
    }

    // Registrar log de sincronización
    await runRun(`
            INSERT INTO sync_logs (device_ip, sync_type, records_count, status, start_time, end_time)
            VALUES (?, 'bulk_sync', ?, 'success', ?, ?)
        `, [device_info.ip, usersInserted + attendanceInserted, startTime.toISOString(), new Date().toISOString()]);

    // Consolidar cambios
    await runRun('COMMIT');

    logger.info(`✅ Sincronización exitosa - IP: ${device_info.ip}, Usuarios: ${usersInserted}, Asistencia: ${attendanceInserted}`);

    res.json({
      success: true,
      message: 'Datos sincronizados correctamente',
      stats: {
        users_processed: usersInserted,
        attendance_processed: attendanceInserted,
        total_processed: usersInserted + attendanceInserted,
        device_ip: device_info.ip,
        sync_time: new Date().toISOString()
      }
    });

    // Procesar envío de mensajes después de responder para evitar timeout en Python
    if (pendingWhatsAppMessages.length > 0) {
      setTimeout(async () => {
        logger.info(`Enviando ${pendingWhatsAppMessages.length} notificaciones de WhatsApp asíncronas...`);
        for (const msg of pendingWhatsAppMessages) {
          await sendWhatsAppMessage(msg.phone, msg.text);
          // Pausa de 500ms entre envíos para no saturar Evolution API
          await new Promise(r => setTimeout(r, 500));
        }
      }, 100);
    }

  } catch (error) {
    logger.error('❌ Error en sincronización:', error);

    // Revertir cambios si la transacción falló
    try {
      await runRun('ROLLBACK');
      logger.info('🔄 Transacción revertida (ROLLBACK) debido a un error.');
    } catch (rollbackError) {
      // Ignorar si no había transacción activa
    }

    // Registrar error en logs (intentar)
    try {
      await runRun(`
                INSERT INTO sync_logs (device_ip, sync_type, records_count, status, error_message, start_time, end_time)
                VALUES (?, 'bulk_sync', 0, 'error', ?, ?, ?)
            `, [device_info?.ip || 'unknown', error.message, startTime.toISOString(), new Date().toISOString()]);
    } catch (e) {
      // Ignorar errores al loguear el error
    }

    res.status(500).json({
      success: false,
      error: 'Error en sincronización',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Endpoint para obtener usuarios
app.get('/api/users', validateApiKey, async (req, res) => {
  try {
    const { page = 1, limit = 50, search, active = true } = req.query;
    const offset = (page - 1) * limit;

    let query = `
            SELECT user_id, uid, name, privilege, email, department, active, device_ip, created_at, updated_at
            FROM users
            WHERE active = ?
        `;

    // SQLite no tiene booleanos nativos, usa 0 y 1
    let activeVal = (active === 'true' || active === true) ? 1 : 0;
    let params = [activeVal];

    if (search) {
      query += ` AND (user_id LIKE ? OR name LIKE ?)`;
      params.push(`%${search}%`);
      params.push(`%${search}%`);
    }

    query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const rows = await runQuery(query, params);

    // Obtener total de registros para paginación
    let countQuery = 'SELECT COUNT(*) as count FROM users WHERE active = ?';
    let countParams = [activeVal];

    if (search) {
      countQuery += ` AND (user_id LIKE ? OR name LIKE ?)`;
      countParams.push(`%${search}%`);
      countParams.push(`%${search}%`);
    }

    const countResult = await runQuery(countQuery, countParams);

    res.json({
      success: true,
      data: rows,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: countResult[0].count,
        pages: Math.ceil(countResult[0].count / limit)
      }
    });
  } catch (error) {
    logger.error('Error obteniendo usuarios:', error);
    res.status(500).json({
      success: false,
      error: 'Error obteniendo usuarios'
    });
  }
});

// Endpoint para obtener registros de asistencia
app.get('/api/attendance', validateApiKey, async (req, res) => {
  try {
    const {
      page = 1,
      limit = 100,
      start_date,
      end_date,
      user_id,
      device_ip,
      punch_type
    } = req.query;

    const offset = (page - 1) * limit;
    let query = `
            SELECT a.id, a.user_id, a.timestamp, a.punch, a.status, a.device_ip,
                   u.name as user_name, u.department, a.created_at
            FROM attendance a
            LEFT JOIN users u ON a.user_id = u.user_id
            WHERE 1=1
        `;
    let params = [];

    if (start_date) {
      query += ` AND DATE(a.timestamp) >= ?`;
      params.push(start_date);
    }

    if (end_date) {
      query += ` AND DATE(a.timestamp) <= ?`;
      params.push(end_date);
    }

    if (user_id) {
      query += ` AND a.user_id = ?`;
      params.push(user_id);
    }

    if (device_ip) {
      query += ` AND a.device_ip = ?`;
      params.push(device_ip);
    }

    if (punch_type !== undefined) {
      query += ` AND a.punch = ?`;
      params.push(parseInt(punch_type));
    }

    query += ` ORDER BY a.timestamp DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const rows = await runQuery(query, params);

    // Obtener total para paginación
    let countQuery = `
            SELECT COUNT(*) as count FROM attendance a
            LEFT JOIN users u ON a.user_id = u.user_id
            WHERE 1=1
        `;
    let countParams = [];

    if (start_date) {
      countQuery += ` AND DATE(a.timestamp) >= ?`;
      countParams.push(start_date);
    }

    if (end_date) {
      countQuery += ` AND DATE(a.timestamp) <= ?`;
      countParams.push(end_date);
    }

    if (user_id) {
      countQuery += ` AND a.user_id = ?`;
      countParams.push(user_id);
    }

    if (device_ip) {
      countQuery += ` AND a.device_ip = ?`;
      countParams.push(device_ip);
    }

    if (punch_type !== undefined) {
      countQuery += ` AND a.punch = ?`;
      countParams.push(parseInt(punch_type));
    }

    const countResult = await runQuery(countQuery, countParams);

    res.json({
      success: true,
      data: rows,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: countResult[0].count,
        pages: Math.ceil(countResult[0].count / limit)
      }
    });
  } catch (error) {
    logger.error('Error obteniendo asistencia:', error);
    res.status(500).json({
      success: false,
      error: 'Error obteniendo registros de asistencia'
    });
  }
});

// Endpoint para obtener estadísticas
app.get('/api/stats', validateApiKey, async (req, res) => {
  try {
    const { period = '7' } = req.query;
    const days = parseInt(period);

    // Estadísticas generales
    const [totalUsers] = await runQuery('SELECT COUNT(*) as count FROM users WHERE active = 1');
    const [totalDevices] = await runQuery("SELECT COUNT(*) as count FROM devices WHERE status = 'active'");
    const [totalAttendance] = await runQuery(`SELECT COUNT(*) as count FROM attendance WHERE date(timestamp) >= date('now', '-${days} days')`);

    // Top usuarios activos
    const topUsers = await runQuery(`
            SELECT u.user_id, u.name, COUNT(a.id) as attendance_count
            FROM users u
            JOIN attendance a ON u.user_id = a.user_id
            WHERE date(a.timestamp) >= date('now', '-${days} days')
            GROUP BY u.user_id, u.name
            ORDER BY attendance_count DESC
            LIMIT 10
        `);

    // Asistencia por día
    const dailyStats = await runQuery(`
            SELECT DATE(timestamp) as date, COUNT(*) as count
            FROM attendance
            WHERE date(timestamp) >= date('now', '-${days} days')
            GROUP BY DATE(timestamp)
            ORDER BY date DESC
        `);

    res.json({
      success: true,
      period: `Últimos ${days} días`,
      stats: {
        total_users: totalUsers.count,
        total_devices: totalDevices.count,
        total_attendance: totalAttendance.count,
        top_users: topUsers,
        daily_stats: dailyStats
      }
    });
  } catch (error) {
    logger.error('Error obteniendo estadísticas:', error);
    res.status(500).json({
      success: false,
      error: 'Error obteniendo estadísticas'
    });
  }
});

// Endpoint para dispositivos
app.get('/api/devices', validateApiKey, async (req, res) => {
  try {
    const rows = await runQuery(`
            SELECT d.*,
                   COUNT(a.id) as attendance_count,
                   MAX(a.timestamp) as last_attendance
            FROM devices d
            LEFT JOIN attendance a ON d.ip = a.device_ip
            GROUP BY d.id, d.ip, d.name, d.location, d.last_seen, d.status, d.created_at, d.updated_at
            ORDER BY d.last_seen DESC
        `);

    res.json({
      success: true,
      data: rows
    });
  } catch (error) {
    logger.error('Error obteniendo dispositivos:', error);
    res.status(500).json({
      success: false,
      error: 'Error obteniendo dispositivos'
    });
  }
});

// Endpoint de logs de sincronización
app.get('/api/sync-logs', validateApiKey, async (req, res) => {
  try {
    const { page = 1, limit = 50, device_ip, status } = req.query;
    const offset = (page - 1) * limit;

    let query = `
            SELECT * FROM sync_logs
            WHERE 1=1
        `;
    let params = [];

    if (device_ip) {
      query += ` AND device_ip = ?`;
      params.push(device_ip);
    }

    if (status) {
      query += ` AND status = ?`;
      params.push(status);
    }

    query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const rows = await runQuery(query, params);

    res.json({
      success: true,
      data: rows,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit)
      }
    });
  } catch (error) {
    logger.error('Error obteniendo logs:', error);
    res.status(500).json({
      success: false,
      error: 'Error obteniendo logs de sincronización'
    });
  }
});

app.get('/api/logs', (req, res) => {
  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  if (apiKey !== process.env.API_KEY) {
    return res.status(401).json({ success: false, error: 'No autorizado' });
  }
  
  try {
    const logPath = path.join(__dirname, 'logs', 'combined.log');
    if (fs.existsSync(logPath)) {
      const logs = fs.readFileSync(logPath, 'utf8').split('\n').slice(-150).join('\n');
      res.type('text/plain').send(logs);
    } else {
      res.status(404).send('No logs found');
    }
  } catch (err) {
    res.status(500).send('Error reading logs');
  }
});

// Manejo de errores
app.use((err, req, res, next) => {
  logger.error('Error no manejado:', err);
  res.status(500).json({
    success: false,
    error: 'Error interno del servidor'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint no encontrado'
  });
});

// Inicialización y inicio del servidor
function startServer() {
  try {
    // Inicializar base de datos
    initializeDatabase();

    // Iniciar servidor
    app.listen(PORT, () => {
      logger.info(`🚀 Servidor API iniciado en puerto ${PORT}`);
      logger.info(`📊 Health check: http://localhost:${PORT}/api/health`);
      logger.info(`🔑 API Key requerida para todos los endpoints`);
      logger.info(`🗄️  Base de datos: ${DB_TYPE}`);
    });
  } catch (error) {
    logger.error('❌ Error iniciando servidor:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('📴 SIGTERM recibido, cerrando servidor...');
  if (db) {
    db.close((err) => {
      if (err) {
        logger.error('Error cerrando BD', err);
      } else {
        logger.info('🔌 Conexiones a base de datos cerradas');
      }
      process.exit(0);
    });
  } else {
    process.exit(0);
  }
});

process.on('SIGINT', () => {
  logger.info('📴 SIGINT recibido, cerrando servidor...');
  if (db) {
    db.close((err) => {
      if (err) {
        logger.error('Error cerrando BD', err);
      } else {
        logger.info('🔌 Conexiones a base de datos cerradas');
      }
      process.exit(0);
    });
  } else {
    process.exit(0);
  }
});

startServer();
