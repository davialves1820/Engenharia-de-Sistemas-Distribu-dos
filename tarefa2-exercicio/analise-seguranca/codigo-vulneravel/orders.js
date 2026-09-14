const express = require('express');
const router = express.Router();

router.get('/orders/:id', authMiddleware, async (req, res) => {
  const order = await db.query(
    `SELECT * FROM orders WHERE id = ${req.params.id}`  // V6
  );
  // V7 sem verificar dono
  res.json(order);
});

router.post('/orders', authMiddleware, async (req, res) => {
  const { items, address, couponCode } = req.body;  // V8 sem validação
  const total = items.reduce((sum, item) => sum + item.price * item.qty, 0);  // V9 preço do cliente
  await db.query(`INSERT INTO orders (user_id, items, total, address)
    VALUES (${req.user.userId}, '${JSON.stringify(items)}', ${total}, '${address}')`);
  res.json({ success: true });
});

router.get('/admin/orders', authMiddleware, async (req, res) => {
  // V10 sem checar admin
  const orders = await db.query('SELECT * FROM orders');
  res.json(orders);
});

module.exports = router;
