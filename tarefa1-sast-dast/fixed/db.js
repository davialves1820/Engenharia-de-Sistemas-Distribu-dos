const bcrypt = require('bcrypt');
// senha "user123"/"admin123" pré-hasheadas
const H = bcrypt.hashSync('user1234', 12);
const HA = bcrypt.hashSync('admin1234', 12);
const users = [
  { id: 1, email: 'admin@gofood.com', password_hash: HA, role: 'admin' },
  { id: 2, email: 'user@gofood.com',  password_hash: H,  role: 'customer' },
];
const products = [{ id: 'b564ae07-a62e-4ca4-8a14-1612c346dcdd', price: 25 }];
const orders = [
  { id: '0fe10a9c-9636-48ce-9104-d7a219138904', user_id: 2, items: '[]', total: 50, address: 'Rua A', status: 'novo' },
  { id: '1ca0298a-a3d4-4ac6-9411-70c56e0c527d', user_id: 1, items: '[]', total: 99, address: 'Rua B', status: 'novo' },
];
// query parametrizada: params são tratados como DADOS, nunca interpolados em SQL
async function query(sql, params = []) {
  const s = sql.replace(/\s+/g,' ').trim();
  if (/FROM users WHERE email = \$1/i.test(s)) {
    const u = users.find(u => u.email === params[0]);   // params[0] é literal, não SQL
    return { rows: u ? [u] : [] };
  }
  if (/FROM users WHERE id = \$1/i.test(s)) {
    const u = users.find(u => u.id === Number(params[0]));
    return { rows: u ? [{ id:u.id, role:u.role }] : [] };
  }
  if (/FROM orders WHERE id = \$1/i.test(s)) {
    const o = orders.find(o => o.id === params[0]);
    return { rows: o ? [o] : [] };
  }
  if (/FROM products WHERE id = ANY/i.test(s)) {
    const ids = params[0];
    return { rows: products.filter(p => ids.includes(p.id)) };
  }
  if (/^INSERT INTO orders/i.test(s)) return { rows: [{ id: '44444444-4444-4444-4444-444444444444' }] };
  if (/FROM orders ORDER BY/i.test(s)) return { rows: orders };
  return { rows: [] };
}
module.exports = { query };
