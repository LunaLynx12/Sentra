import React from 'react';
import { Shield, Twitter, Github as GitHub, Mail } from 'lucide-react';

const Footer: React.FC = () => {
  return (
    <footer className="bg-gray-900 text-gray-300 py-10 mt-16">
      <div className="container mx-auto px-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div className="space-y-4">
            <div className="flex items-center space-x-2">
              <Shield className="text-blue-400 h-6 w-6" />
              <h3 className="text-xl font-bold text-white">Sentra <span className="text-blue-400">by WannaCryptic</span></h3>
            </div>
            <p className="text-sm text-gray-400">
              A lightweight solution for scanning files, images, and URLs for malicious content.
            </p>
            <div className="flex space-x-4 pt-2">
              <a href="#" className="text-gray-400 hover:text-white transition-colors">
                <Twitter className="h-5 w-5" />
              </a>
              <a href="#" className="text-gray-400 hover:text-white transition-colors">
                <GitHub className="h-5 w-5" />
              </a>
              <a href="#" className="text-gray-400 hover:text-white transition-colors">
                <Mail className="h-5 w-5" />
              </a>
            </div>
          </div>
          
          <div>
            <h4 className="text-white font-semibold mb-4">Features</h4>
            <ul className="space-y-2 text-sm">
              <li><a href="#" className="text-gray-400 hover:text-white transition-colors">File Scanning</a></li>
              <li><a href="#" className="text-gray-400 hover:text-white transition-colors">URL Analysis</a></li>
              <li><a href="#" className="text-gray-400 hover:text-white transition-colors">Threat Detection</a></li>
              <li><a href="#" className="text-gray-400 hover:text-white transition-colors">Scan History</a></li>
            </ul>
          </div>
          
          <div>
            <h4 className="text-white font-semibold mb-4">Resources</h4>
            <ul className="space-y-2 text-sm">
              <li><a href="#" className="text-gray-400 hover:text-white transition-colors">Documentation</a></li>
              <li><a href="#" className="text-gray-400 hover:text-white transition-colors">API</a></li>
              <li><a href="#" className="text-gray-400 hover:text-white transition-colors">Blog</a></li>
              <li><a href="#" className="text-gray-400 hover:text-white transition-colors">Support</a></li>
            </ul>
          </div>
          
          <div>
            <h4 className="text-white font-semibold mb-4">Legal</h4>
            <ul className="space-y-2 text-sm">
              <li><a href="#" className="text-gray-400 hover:text-white transition-colors">Privacy Policy</a></li>
              <li><a href="#" className="text-gray-400 hover:text-white transition-colors">Terms of Service</a></li>
              <li><a href="#" className="text-gray-400 hover:text-white transition-colors">Cookies</a></li>
              <li><a href="#" className="text-gray-400 hover:text-white transition-colors">GDPR</a></li>
            </ul>
          </div>
        </div>
        
        <div className="border-t border-gray-800 mt-8 pt-6 text-center text-sm text-gray-500">
          <p>&copy; {new Date().getFullYear()} Sentra by WannaCryptic. All rights reserved.</p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;