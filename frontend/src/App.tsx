import React, { useState, useEffect } from 'react';
import HomePage from './pages/HomePage';
import ScannerPage from './pages/ScannerPage';
import SignInPage from './pages/SignInPage';
import RegisterPage from './pages/RegisterPage';

function App() {
  const [currentPage, setCurrentPage] = useState<'home' | 'scanner' | 'signin' | 'register'>('home');
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // Navigation handler via click events
  useEffect(() => {
    const handleNavigation = (e: MouseEvent) => {
      const target = e.target as HTMLElement;

      if (!target || !target.textContent) return;

      switch (target.textContent.trim()) {
        case 'Start Scanning':
        case 'Go to Scanner':
          e.preventDefault();
          setCurrentPage('scanner');
          break;

        case 'Documentation':
        case 'Learn More':
        case 'About':
        case 'Report threats':
          e.preventDefault();
          window.location.href = 'https://github.com/LunaLynx12/Hackathon/blob/main/README.md ';
          break;

        case 'Sign In':
          e.preventDefault();
          setCurrentPage('signin');
          break;

        case 'Home':
          e.preventDefault();
          setCurrentPage('home');
          break;

        default:
          break;
      }
    };

    document.addEventListener('click', handleNavigation);
    return () => {
      document.removeEventListener('click', handleNavigation);
    };
  }, []);

  return (
    <>
      {currentPage === 'home' && <HomePage />}
      {currentPage === 'scanner' && <ScannerPage />}
      {currentPage === 'signin' && (
        <SignInPage
          onLogin={() => {
            setIsAuthenticated(true);
            setCurrentPage('scanner');
          }}
        />
      )}
      {currentPage === 'register' && (
        <RegisterPage
          onRegister={() => {
            setIsAuthenticated(true);
            setCurrentPage('scanner');
          }}
        />
      )}
    </>
  );
}

export default App;