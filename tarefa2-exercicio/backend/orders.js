const express = require('express');
const { z } = require('zod');
const db = require('./db');
const { authMiddleware } = require('./auth');

const router = express.Router();

const orderSchema = z.object({
  items: z.array(z.object({
    productId: z.string().uuid(),
    qty: z.number().int().positive().max(100),
  })).min(1).max(50),
  address: z.string().min(5).max(300),
  couponCode: z.string().max(40).optional(),
});

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Acesso negado' });
    }
    next();
  };
}

router.get('/orders/:id', authMiddleware, async (req, res, next) => {
  try {
    const id = z.string().uuid().parse(req.params.id);
    const { rows } = await db.query(
      'SELECT id, user_id, items, total, address, status FROM orders WHERE id = $1',
      [id]
    );
    const order = rows[0];
    if (!order) return res.status(404).json({ error: 'Pedido não encontrado' });
    if (order.user_id !== req.user.userId && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Acesso negado' });
    }
    return res.json(order);
  } catch (err) {
    if (err?.name === 'ZodError') return res.status(400).json({ error: 'ID inválido' });
    next(err);
  }
});

router.post('/orders', authMiddleware, async (req, res, next) => {
  try {
    const { items, address } = orderSchema.parse(req.body);
    const ids = items.map(i => i.productId);
    const { rows: products } = await db.query('SELECT id, price FROM products WHERE id = ANY($1)', [ids]);
    const priceMap = new Map(products.map(p => [p.id, Number(p.price)]));
    if (priceMap.size !== ids.length) {
      return res.status(400).json({ error: 'Produto inexistente no pedido' });
    }
    const total = items.reduce((sum, i) => sum + priceMap.get(i.productId) * i.qty, 0);
    const { rows } = await db.query(
      `INSERT INTO orders (user_id, items, total, address) VALUES ($1, $2, $3, $4) RETURNING id`,
      [req.user.userId, JSON.stringify(items), total, address]
    );
    return res.status(201).json({ id: rows[0].id, total });
  } catch (err) {
    if (err?.name === 'ZodError') return res.status(400).json({ error: 'Dados inválidos' });
    next(err);
  }
});

router.get('/admin/orders', authMiddleware, requireRole('admin'), async (req, res, next) => {
  try {
    const { rows } = await db.query(
      'SELECT id, user_id, total, status, created_at FROM orders ORDER BY created_at DESC LIMIT 200'
    );
    return res.json(rows);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
