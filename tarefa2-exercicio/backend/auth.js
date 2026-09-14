const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const { z } = require('zod');
const db = require('./db');

const router = express.Router();
router.use(cookieParser());

const ACCESS_SECRET  = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
if (!ACCESS_SECRET || !REFRESH_SECRET) {
  throw new Error('JWT secrets não configurados no ambiente');
}
const ACCESS_TTL = '15m';
const REFRESH_TTL = '7d';
const cookieOpts = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  path: '/',
};
const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(200),
});

router.post('/login', async (req, res, next) => {
  try {
    const { email, password } = loginSchema.parse(req.body);
    const { rows } = await db.query(
      'SELECT id, email, password_hash, role FROM users WHERE email = $1',
      [email]
    );
    const user = rows[0];
    const hash = user?.password_hash ?? '$2b$12$invalidinvalidinvalidinvalidinva';
    const ok = await bcrypt.compare(password, hash);
    if (!user || !ok) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }
    const accessToken = jwt.sign({ sub: user.id, role: user.role }, ACCESS_SECRET, { expiresIn: ACCESS_TTL });
    const refreshToken = jwt.sign({ sub: user.id, type: 'refresh' }, REFRESH_SECRET, { expiresIn: REFRESH_TTL });
    res.cookie('access_token', accessToken, { ...cookieOpts, maxAge: 15 * 60 * 1000 });
    res.cookie('refresh_token', refreshToken, { ...cookieOpts, path: '/api/auth/refresh', maxAge: 7 * 24 * 60 * 60 * 1000 });
    return res.json({ user: { id: user.id, email: user.email } });
  } catch (err) {
    if (err?.name === 'ZodError') return res.status(400).json({ error: 'Dados inválidos' });
    next(err);
  }
});

router.post('/refresh', async (req, res) => {
  const token = req.cookies?.refresh_token;
  if (!token) return res.status(401).json({ error: 'Sem refresh token' });
  try {
    const payload = jwt.verify(token, REFRESH_SECRET);
    if (payload.type !== 'refresh') throw new Error('tipo inválido');
    const { rows } = await db.query('SELECT id, role FROM users WHERE id = $1', [payload.sub]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'Usuário inválido' });
    const accessToken = jwt.sign({ sub: user.id, role: user.role }, ACCESS_SECRET, { expiresIn: ACCESS_TTL });
    res.cookie('access_token', accessToken, { ...cookieOpts, maxAge: 15 * 60 * 1000 });
    return res.json({ ok: true });
  } catch {
    return res.status(401).json({ error: 'Refresh token inválido' });
  }
});

function authMiddleware(req, res, next) {
  const token = req.cookies?.access_token;
  if (!token) return res.status(401).json({ error: 'Não autenticado' });
  try {
    const payload = jwt.verify(token, ACCESS_SECRET);
    req.user = { userId: payload.sub, role: payload.role };
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido ou expirado' });
  }
}

module.exports = { router, authMiddleware };
