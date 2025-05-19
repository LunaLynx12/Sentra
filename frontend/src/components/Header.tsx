import React from 'react';
import { Shield, AlertTriangle, Menu } from 'lucide-react';
import { useState } from 'react';

const Header: React.FC = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  return (
    <header className="bg-white shadow-sm fixed top-0 left-0 right-0 z-10">
      <div className="container mx-auto px-4 py-3 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Shield className="text-blue-600 h-8 w-8" />
          <h1 className="text-2xl font-bold text-gray-800">Sentra <span className="text-blue-600">by WannaCryptic</span></h1>
        </div>
        
        <div className="hidden md:flex items-center space-x-8">
          <nav className="flex items-center space-x-6">
            <a href="#" className="text-gray-700 hover:text-blue-600 font-medium transition-colors">Home</a>
            <a href="#" className="text-gray-700 hover:text-blue-600 font-medium transition-colors">About</a>
            <a href="#" className="text-gray-700 hover:text-blue-600 font-medium transition-colors">Documentation</a>
          </nav>
          
          <div className="flex items-center space-x-4">
            <button className="flex items-center space-x-1 px-3 py-1 bg-amber-100 text-amber-800 rounded-full text-sm hover:bg-amber-200 transition-colors">
              <AlertTriangle className="h-4 w-4" />
              <span>Report threats</span>
            </button>
            <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium">
              Sign In
            </button>
          </div>
        </div>
        
        <button 
          className="md:hidden text-gray-700"
          onClick={() => setIsMenuOpen(!isMenuOpen)}
        >
          <Menu className="h-6 w-6" />
        </button>
      </div>
      
      {/* Mobile menu */}
      {isMenuOpen && (
        <div className="md:hidden bg-white border-t py-3 px-4 shadow-lg">
          <nav className="flex flex-col space-y-3">
            <a href="#" className="text-gray-700 hover:text-blue-600 font-medium transition-colors">Home</a>
            <a href="#" className="text-gray-700 hover:text-blue-600 font-medium transition-colors">About</a>
            <a href="#" className="text-gray-700 hover:text-blue-600 font-medium transition-colors">Documentation</a>
            <div className="pt-2 flex flex-col space-y-2">
              <button className="flex items-center justify-center space-x-1 px-3 py-2 bg-amber-100 text-amber-800 rounded-full text-sm hover:bg-amber-200 transition-colors">
                <AlertTriangle className="h-4 w-4" />
                <span>Report threats</span>
              </button>
              <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium">
                Sign In
              </button>
            </div>
          </nav>
        </div>
      )}
    </header>
  );
};

export default Header;