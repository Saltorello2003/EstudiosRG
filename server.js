require('dotenv').config();

const express = require('express');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();

// Configurações Globais
app.use(express.json({ limit: '100kb' }));
app.use(cors({
  origin: true, // Permitir todas as origens para facilitar o deploy no Render
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Servir o front-end (index.html) - ISSO RESOLVE O "Cannot GET /"
app.use(express.static(path.join(__dirname)));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'development' ? false : { rejectUnauthorized: false },
  max: 10
});

const JWT_SECRET = process.env.JWT_SECRET || 'chave-segura-aqui';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'saltorello2003@gmail.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const PORT = process.env.PORT || 10000; // Porta padrão do Render

// Middleware de Auth
function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Acesso negado.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(403).json({ error: 'Token inválido.' });
  }
}

// Inicialização do Banco
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
      UNIQUE(profissional, data, horario)
    );
  `);
  
  const result = await pool.query('SELECT id FROM usuarios WHERE email = $1', [ADMIN_EMAIL]);
  if (!result.rowCount) {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
    await pool.query('INSERT INTO usuarios (email, senha, role) VALUES ($1, $2, $3)', [ADMIN_EMAIL, hash, 'admin']);
    console.log('Admin inicial criado.');
  }
}

// Rotas de API
app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.post('/api/auth/login', async (req, res) => {
  const { email, senha } = req.body;
  const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
  if (result.rowCount && await bcrypt.compare(String(senha), result.rows[0].senha)) {
    const token = jwt.sign({ id: result.rows[0].id }, JWT_SECRET, { expiresIn: '8h' });
    return res.json({ token });
  }
  res.status(401).json({ message: 'Login falhou' });
});

// Rota para servir o index.html (SPA)
// IMPORTANTE: Deve vir APÓS as rotas de API
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

async function start() {
  await initDB();
  app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
}

start();