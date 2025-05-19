import React, { useState } from 'react';
import axios from 'axios';

const SignInPage = ({ onLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleLogin = async () => {
    try {
      const res = await axios.post('http://localhost:8100/auth/token', {
        username,
        password
      }, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      localStorage.setItem('token', res.data.access_token);
      onLogin();
    } catch (err) {
      setError("Invalid credentials");
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-100">
      <h2 className="text-xl font-bold mb-4">Sign In</h2>
      {error && <p className="text-red-500">{error}</p>}
      <input
        type="text"
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        className="border p-2 mb-2 w-64"
      />
      <input
        type="password"
        placeholder="Password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        className="border p-2 mb-2 w-64"
      />
      <button onClick={handleLogin} className="bg-blue-500 text-white px-4 py-2 rounded">
        Login
      </button>
      <p className="mt-2">
        Don't have an account?{' '}
        <a href="/register" className="text-blue-500 underline">Register</a>
      </p>
    </div>
  );
};

export default SignInPage;