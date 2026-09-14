// Mock DB que executa uma simulação ingênua de SQL sobre dados em memória.
// Reproduz a vulnerabilidade: interpreta ' OR '1'='1' e UNION de forma insegura.
const users = [
  { id: 1, email: 'admin@gofood.com', password: 'admin123', role: 'admin' },
  { id: 2, email: 'user@gofood.com',  password: 'user123',  role: 'customer' },
];
const orders = [
  { id: 1, user_id: 2, items: '[]', total: 50, address: 'Rua A' },
  { id: 2, user_id: 1, items: '[]', total: 99, address: 'Rua B' },
];

async function query(sql) {
  const s = sql.replace(/\s+/g, ' ').trim();

  // SELECT * FROM users WHERE email = '...' AND password = '...'
  if (/SELECT \* FROM users WHERE email =/i.test(s)) {
    // V2: tautologia ' OR '1'='1' -> retorna admin (primeiro usuário)
    if (/OR '1'='1'/i.test(s) || /OR 1=1/i.test(s)) return users[0];
    const m = s.match(/email = '([^']*)' AND password = '([^']*)'/i);
    if (m) return users.find(u => u.email === m[1] && u.password === m[2]) || null;
    return null;
  }

  // SELECT * FROM orders WHERE id = <x>   (com possível UNION)
  if (/SELECT \* FROM orders WHERE id =/i.test(s)) {
    // V6: UNION SELECT ... FROM users -> vaza usuários (inclui senha)
    if (/UNION SELECT/i.test(s) && /FROM users/i.test(s)) {
      return users.map(u => ({ id: u.id, email: u.email, password: u.password, role: u.role }));
    }
    const m = s.match(/id = (\d+)/i);
    if (m) return orders.find(o => o.id === Number(m[1])) || null;
    return null;
  }

  if (/SELECT \* FROM orders$/i.test(s)) return orders;      // /admin/orders
  if (/^INSERT INTO orders/i.test(s)) return { insertId: 3 }; // criar pedido
  return null;
}
module.exports = { query };
