const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();

const SECRET = "gofood2024secret";  // V1

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;  // V2
  const user = await db.query(query);
  if (!user) {
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }
  const token = jwt.sign(
    { userId: user.id, role: user.role, email: user.email },
    SECRET   // V3 sem expiração
  );
  res.json({ token, userId: user.id, role: user.role });  // V4
});

function authMiddleware(req, res, next) {
  const token = req.headers.authorization;  // V5
  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token inválido' });
  }
}

module.exports = { router, authMiddleware };
