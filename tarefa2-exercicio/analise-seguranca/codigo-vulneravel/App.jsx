import React, { useState } from 'react';

function App() {
  const [user, setUser] = useState(null);

  async function handleLogin(email, password) {
    const res = await fetch('http://localhost:3000/api/login', {  // V11
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();
    localStorage.setItem('token', data.token);   // V12
    localStorage.setItem('role', data.role);     // V13
    setUser(data);
  }

  function AdminPanel() {
    if (localStorage.getItem('role') !== 'admin') return null;  // V14
    return <div>Painel Admin...</div>;
  }

  function ProductComments({ comments }) {
    return (
      <div>
        {comments.map(c => (
          <div key={c.id} dangerouslySetInnerHTML={{ __html: c.text }} />  /* V15 */
        ))}
      </div>
    );
  }

  return (<div />);
}
export default App;
