require('dotenv').config();

const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL;
const email = (process.env.ADMIN_EMAIL || 'saltorello2003@gmail.com').trim().toLowerCase();
const novaSenha = process.env.ADMIN_PASSWORD;

if (!connectionString) {
  console.error('❌ DATABASE_URL não configurada.');
  process.exit(1);
}

if (!novaSenha || novaSenha.length < 8) {
  console.error('❌ Defina ADMIN_PASSWORD no ambiente com pelo menos 8 caracteres.');
  process.exit(1);
}

const pool = new Pool({
  connectionString,
  ssl: process.env.NODE_ENV === 'development' ? false : { rejectUnauthorized: false }
});

async function resetar() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        senha VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'admin'
      );
    `);

    const hash = await bcrypt.hash(novaSenha, 12);

    await pool.query(`
      INSERT INTO usuarios (email, senha, role)
      VALUES ($1, $2, 'admin')
      ON CONFLICT (email)
      DO UPDATE SET senha = EXCLUDED.senha, role = 'admin'
    `, [email]);

    console.log('✅ Usuário administrador atualizado com sucesso.');
    console.log(`E-mail: ${email}`);
    console.log('Senha: definida pela variável ADMIN_PASSWORD (não exibida por segurança).');
  } catch (err) {
    console.error('❌ Erro ao redefinir administrador:', err);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

resetar();