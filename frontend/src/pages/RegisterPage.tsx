import React, { useState } from 'react';
import axios from 'axios';

const RegisterPage = ({ onRegister }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');

  const handleRegister = async () => {
    try {
      await axios.post('http://localhost:8100/auth/register', {
        username,
        password,
        email
      });
      onRegister();
    } catch (err) {
      setError("Registration failed");
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-100">
      <h2 className="text-xl font-bold mb-4">Register</h2>
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
      <input
        type="email"
        placeholder="Email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        className="border p-2 mb-2 w-64"
      />
      <button onClick={handleRegister} className="bg-green-500 text-white px-4 py-2 rounded">
        Register
      </button>
      <p className="mt-2">
        Already have an account?{' '}
        <a href="/signin" className="text-blue-500 underline">Sign In</a>
      </p>
    </div>
  );
};

export default RegisterPage;