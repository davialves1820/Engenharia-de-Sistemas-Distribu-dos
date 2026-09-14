const express = require('express');
const router = express.Router();
const db = require('./db');
const { authMiddleware } = require('./auth');

router.get('/orders/:id', authMiddleware, async (req, res) => {
  const order = await db.query(`SELECT * FROM orders WHERE id = ${req.params.id}`);  // V6
  res.json(order);  // V7 sem checar dono
});

router.post('/orders', authMiddleware, async (req, res) => {
  const { items, address } = req.body;  // V8
  const total = items.reduce((s, i) => s + i.price * i.qty, 0);  // V9 preço do cliente
  await db.query(`INSERT INTO orders (user_id, items, total, address) VALUES (${req.user.userId}, '${JSON.stringify(items)}', ${total}, '${address}')`);
  res.json({ success: true });
});

router.get('/admin/orders', authMiddleware, async (req, res) => {
  const orders = await db.query('SELECT * FROM orders');  // V10 sem checar admin
  res.json(orders);
});
module.exports = router;
