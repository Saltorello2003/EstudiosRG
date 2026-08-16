require('dotenv').config();

const express = require('express');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.use(express.json({ limit: '100kb' }));
app.use(cors({
  origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',').map(x => x.trim()) : true,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Servir o front-end na mesma aplicação
app.use(express.static(path.join(__dirname)));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'development' ? false : { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const JWT_SECRET = process.env.JWT_SECRET || 'troque-esta-chave-em-producao';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'saltorello2003@gmail.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const PORT = Number(process.env.PORT) || 3000;

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Acesso negado.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(403).json({ error: 'Sessão expirada ou token inválido.' });
  }
}

function normalizePhone(v) {
  return String(v || '').replace(/\D/g, '');
}

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      senha VARCHAR(255) NOT NULL,
      role VARCHAR(50) DEFAULT 'admin'
    );

    CREATE TABLE IF NOT EXISTS agendamentos (
      id SERIAL PRIMARY KEY,
      cliente_nome VARCHAR(255) NOT NULL,
      cliente_telefone VARCHAR(50) NOT NULL,
      servico VARCHAR(255) NOT NULL,
      preco NUMERIC(10,2) DEFAULT 0,
      profissional VARCHAR(100) NOT NULL,
      data DATE NOT NULL,
      horario VARCHAR(20) NOT NULL,
      status VARCHAR(50) DEFAULT 'pendente',
      criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS horarios_bloqueados (
      id SERIAL PRIMARY KEY,
      profissional VARCHAR(100) NOT NULL,
      data DATE NOT NULL,
      horario VARCHAR(20) NOT NULL,
      criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(profissional, data, horario)
    );

    ALTER TABLE agendamentos ADD COLUMN IF NOT EXISTS preco NUMERIC(10,2) DEFAULT 0;
    ALTER TABLE agendamentos ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'pendente';
    ALTER TABLE agendamentos ADD COLUMN IF NOT EXISTS criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

    CREATE UNIQUE INDEX IF NOT EXISTS agendamento_horario_unico
      ON agendamentos(data, horario, profissional)
      WHERE status <> 'cancelado';
  `);

  const result = await pool.query('SELECT id FROM usuarios WHERE email = $1', [ADMIN_EMAIL]);
  if (!result.rowCount) {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
    await pool.query(
      'INSERT INTO usuarios (email, senha, role) VALUES ($1, $2, $3)',
      [ADMIN_EMAIL, hash, 'admin']
    );
    console.log(`Admin criado: ${ADMIN_EMAIL}`);
  }
}

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'Estudios RG API' });
  } catch {
    res.status(503).json({ ok: false, service: 'database unavailable' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const senha = req.body.senha || req.body.password;
  if (!email || !senha) return res.status(400).json({ message: 'E-mail e senha são obrigatórios.' });

  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE LOWER(email) = $1', [email]);
    if (!result.rowCount) return res.status(401).json({ message: 'E-mail ou senha incorretos.' });

    const user = result.rows[0];
    const valid = await bcrypt.compare(String(senha), user.senha);
    if (!valid) return res.status(401).json({ message: 'E-mail ou senha incorretos.' });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({ token, usuario: { id: user.id, email: user.email, role: user.role } });
  } catch (err) {
    console.error('Login:', err);
    res.status(500).json({ message: 'Erro interno no servidor.' });
  }
});

app.get('/api/agendamentos/publicos', async (req, res) => {
  try {
    const [appointments, blocks] = await Promise.all([
      pool.query(`
        SELECT data, horario, profissional, status
        FROM agendamentos
        WHERE status <> 'cancelado'
      `),
      pool.query(`
        SELECT data, horario, profissional
        FROM horarios_bloqueados
      `)
    ]);
    res.json({ agendamentos: appointments.rows, bloqueios: blocks.rows });
  } catch (err) {
    console.error('Públicos:', err);
    res.status(500).json({ message: 'Erro ao consultar disponibilidade.' });
  }
});

app.post('/api/agendamentos', async (req, res) => {
  const { nome, telefone, servico, preco, data, horario, profissional } = req.body;
  const cleanName = String(nome || '').trim();
  const cleanPhoneNum = normalizePhone(telefone);
  const cleanService = String(servico || '').trim();
  const cleanPro = String(profissional || '').trim();
  const numericPrice = Number(preco);

  if (!cleanName || cleanName.length > 120 || cleanPhoneNum.length < 10 ||
      !cleanService || !cleanPro || !data || !horario || !Number.isFinite(numericPrice) || numericPrice < 0) {
    return res.status(400).json({ message: 'Dados do agendamento inválidos.' });
  }

  try {
    const blocked = await pool.query(
      'SELECT 1 FROM horarios_bloqueados WHERE profissional = $1 AND data = $2 AND horario = $3',
      [cleanPro, data, horario]
    );
    if (blocked.rowCount) return res.status(409).json({ message: 'Este horário está bloqueado.' });

    const result = await pool.query(`
      INSERT INTO agendamentos
        (cliente_nome, cliente_telefone, servico, preco, profissional, data, horario)
      VALUES ($1,$2,$3,$4,$5,$6,$7)
      RETURNING *
    `, [cleanName, cleanPhoneNum, cleanService, numericPrice, cleanPro, data, horario]);

    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ message: 'Este horário acabou de ser reservado por outra pessoa. Escolha outro.' });
    }
    console.error('Criar agendamento:', err);
    res.status(500).json({ message: 'Erro ao criar agendamento.' });
  }
});

app.get('/api/agendamentos/cliente', async (req, res) => {
  const phone = normalizePhone(req.query.telefone);
  if (phone.length < 10) return res.status(400).json({ message: 'Telefone inválido.' });

  try {
    const result = await pool.query(`
      SELECT id, cliente_nome, cliente_telefone, servico, preco, profissional, data, horario, status
      FROM agendamentos
      WHERE regexp_replace(cliente_telefone, '\\D', '', 'g') = $1
        AND status <> 'cancelado'
      ORDER BY data ASC, horario ASC
    `, [phone]);
    res.json(result.rows);
  } catch (err) {
    console.error('Consulta cliente:', err);
    res.status(500).json({ message: 'Erro ao consultar seus agendamentos.' });
  }
});

app.get('/api/agendamentos', auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT *
      FROM agendamentos
      ORDER BY data ASC, horario ASC, criado_em ASC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error('Admin agendamentos:', err);
    res.status(500).json({ message: 'Erro ao buscar agendamentos.' });
  }
});

app.delete('/api/agendamentos/:id', auth, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ message: 'ID inválido.' });

  try {
    const result = await pool.query(
      `UPDATE agendamentos SET status = 'cancelado' WHERE id = $1 RETURNING id`,
      [id]
    );
    if (!result.rowCount) return res.status(404).json({ message: 'Agendamento não encontrado.' });
    res.json({ message: 'Agendamento cancelado.' });
  } catch (err) {
    console.error('Cancelar:', err);
    res.status(500).json({ message: 'Erro ao cancelar agendamento.' });
  }
});

app.get('/api/horarios/bloqueados', async (req, res) => {
  try {
    const result = await pool.query('SELECT data, horario, profissional FROM horarios_bloqueados ORDER BY data, horario');
    res.json(result.rows);
  } catch (err) {
    console.error('Bloqueios:', err);
    res.status(500).json({ message: 'Erro ao buscar bloqueios.' });
  }
});

app.post('/api/horarios/bloqueados', auth, async (req, res) => {
  const profissional = String(req.body.profissional || '').trim();
  const data = req.body.data;
  const horario = req.body.horario;
  if (!profissional || !data || !horario) return res.status(400).json({ message: 'Dados do bloqueio inválidos.' });

  try {
    const result = await pool.query(`
      INSERT INTO horarios_bloqueados (profissional, data, horario)
      VALUES ($1,$2,$3)
      ON CONFLICT (profissional,data,horario) DO NOTHING
      RETURNING *
    `, [profissional, data, horario]);

    if (!result.rowCount) return res.status(200).json({ message: 'Horário já estava bloqueado.' });
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Bloquear:', err);
    res.status(500).json({ message: 'Erro ao bloquear horário.' });
  }
});

app.delete('/api/horarios/bloqueados', auth, async (req, res) => {
  const profissional = String(req.query.profissional || '').trim();
  const { data, horario } = req.query;
  if (!profissional || !data || !horario) return res.status(400).json({ message: 'Dados inválidos.' });

  try {
    await pool.query(
      'DELETE FROM horarios_bloqueados WHERE profissional = $1 AND data = $2 AND horario = $3',
      [profissional, data, horario]
    );
    res.json({ message: 'Horário desbloqueado.' });
  } catch (err) {
    console.error('Desbloquear:', err);
    res.status(500).json({ message: 'Erro ao desbloquear horário.' });
  }
});

// Qualquer outra rota redireciona para o index.html (SPA fallback)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

async function start() {
  try {
    await initDB();
    app.listen(PORT, () => console.log(`Servidor Estudios RG rodando na porta ${PORT}`));
  } catch (err) {
    console.error('Falha ao iniciar:', err);
    process.exit(1);
  }
}

process.on('SIGTERM', async () => {
  await pool.end();
  process.exit(0);
});
process.on('SIGINT', async () => {
  await pool.end();
  process.exit(0);
});

start();