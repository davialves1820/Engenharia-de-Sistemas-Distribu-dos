import React, { useState, useEffect } from 'react';
import DOMPurify from 'dompurify';

const API = 'https://api.gofood.com';

async function api(path, options = {}) {
  const res = await fetch(`${API}${path}`, {
    ...options,
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
  });
  return res;
}

function App() {
  const [user, setUser] = useState(null);
  const [isAdmin, setIsAdmin] = useState(false);

  useEffect(() => { checkAdminAccess(); }, []);

  async function handleLogin(email, password) {
    const res = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) });
    if (!res.ok) { setUser(null); return; }
    const data = await res.json();
    setUser(data.user);
    await checkAdminAccess();
  }

  async function checkAdminAccess() {
    const res = await api('/api/me');
    if (!res.ok) { setIsAdmin(false); setUser(null); return; }
    const me = await res.json();
    setUser(me.user);
    setIsAdmin(me.role === 'admin');
  }

  function AdminPanel() {
    if (!isAdmin) return null;
    return <div>Painel Admin…</div>;
  }

  function ProductComments({ comments }) {
    return (
      <div>
        {comments.map(c => (<div key={c.id}>{c.text}</div>))}
      </div>
    );
  }

  function RichComment({ html }) {
    const clean = DOMPurify.sanitize(html, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
      ALLOWED_ATTR: ['href'],
    });
    return <div dangerouslySetInnerHTML={{ __html: clean }} />;
  }

  return (<div />);
}
export default App;
