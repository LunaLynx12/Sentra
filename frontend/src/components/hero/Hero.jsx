import React from 'react';
import { Shield, FileText, Link2, Check } from 'lucide-react';

const Hero = () => {
  return (
    <div className="bg-gradient-to-b from-blue-50 to-white py-16 md:py-24">
      <div className="container mx-auto px-4">
        <div className="max-w-4xl mx-auto text-center">
          <div className="inline-flex items-center justify-center p-2 bg-blue-100 rounded-full mb-6">
            <Shield className="text-blue-600 h-6 w-6" />
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-gray-900 mb-6">
            Analyze files and URLs for <span className="text-blue-600">threats</span>
          </h1>
          <p className="text-xl text-gray-600 mb-8 leading-relaxed">
            Sentra by WannaCryptic helps you identify malicious content by scanning files and URLs with multiple security engines, all in one simple interface.
          </p>
          <div className="flex flex-wrap justify-center gap-4 mb-10">
            <button className="px-6 py-3 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 transition-colors shadow-md">
              Start Scanning
            </button>
            <button className="px-6 py-3 bg-white text-blue-600 font-semibold rounded-lg border border-blue-200 hover:bg-blue-50 transition-colors shadow-sm">
              Learn More
            </button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-16">
            <div className="bg-white p-6 rounded-lg shadow-sm border">
              <div className="bg-blue-100 w-12 h-12 rounded-full flex items-center justify-center mb-4 mx-auto">
                <FileText className="text-blue-600 h-6 w-6" />
              </div>
              <h3 className="text-lg font-semibold text-gray-800 mb-2">File Scanning</h3>
              <p className="text-gray-600 text-sm">
                Analyze binaries, documents, images and more using multiple security engines
              </p>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border">
              <div className="bg-blue-100 w-12 h-12 rounded-full flex items-center justify-center mb-4 mx-auto">
                <Link2 className="text-blue-600 h-6 w-6" />
              </div>
              <h3 className="text-lg font-semibold text-gray-800 mb-2">URL Analysis</h3>
              <p className="text-gray-600 text-sm">
                Check websites for phishing, malware and other suspicious content
              </p>
            </div>
            
            <div className="bg-white p-6 rounded-lg shadow-sm border">
              <div className="bg-blue-100 w-12 h-12 rounded-full flex items-center justify-center mb-4 mx-auto">
                <Check className="text-blue-600 h-6 w-6" />
              </div>
              <h3 className="text-lg font-semibold text-gray-800 mb-2">Detailed Reports</h3>
              <p className="text-gray-600 text-sm">
                Get comprehensive scan results with detailed information about potential threats
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Hero;