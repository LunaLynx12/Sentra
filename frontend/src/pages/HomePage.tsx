import React from 'react';
import Hero from '../components/hero/Hero';
import Header from '../components/Header';
import Footer from '../components/Footer';

const HomePage: React.FC = () => {
  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      <Header />
      <main className="flex-grow pt-16">
        <Hero />
        <div className="container mx-auto px-4 py-16">
          <div className="max-w-4xl mx-auto">
            <h2 className="text-3xl font-bold text-gray-900 mb-6 text-center">How It Works</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-10">
              <div className="bg-white p-6 rounded-lg shadow-sm border relative">
                <div className="absolute -top-4 left-1/2 transform -translate-x-1/2 bg-blue-600 w-8 h-8 rounded-full flex items-center justify-center text-white font-bold">
                  1
                </div>
                <h3 className="text-lg font-semibold text-gray-800 mb-2 mt-4 text-center">Upload</h3>
                <p className="text-gray-600 text-sm text-center">
                  Upload a file or submit a URL that you want to analyze for potential threats
                </p>
              </div>
              
              <div className="bg-white p-6 rounded-lg shadow-sm border relative">
                <div className="absolute -top-4 left-1/2 transform -translate-x-1/2 bg-blue-600 w-8 h-8 rounded-full flex items-center justify-center text-white font-bold">
                  2
                </div>
                <h3 className="text-lg font-semibold text-gray-800 mb-2 mt-4 text-center">Analyze</h3>
                <p className="text-gray-600 text-sm text-center">
                  Our system scans the content using multiple security engines to detect threats
                </p>
              </div>
              
              <div className="bg-white p-6 rounded-lg shadow-sm border relative">
                <div className="absolute -top-4 left-1/2 transform -translate-x-1/2 bg-blue-600 w-8 h-8 rounded-full flex items-center justify-center text-white font-bold">
                  3
                </div>
                <h3 className="text-lg font-semibold text-gray-800 mb-2 mt-4 text-center">Results</h3>
                <p className="text-gray-600 text-sm text-center">
                  Get detailed scan results and actionable information about potential threats
                </p>
              </div>
            </div>
            
            <div className="bg-blue-600 text-white rounded-xl p-8 mt-16 text-center">
              <h3 className="text-2xl font-bold mb-4">Ready to scan for threats?</h3>
              <p className="mb-6">Start using our scanning tools to check files and URLs for malicious content.</p>
              <button className="px-6 py-3 bg-white text-blue-600 font-semibold rounded-lg hover:bg-blue-50 transition-colors">
                Go to Scanner
              </button>
            </div>
            
            {/* Trust section */}
            <div className="mt-20">
              <h2 className="text-3xl font-bold text-gray-900 mb-10 text-center">Trusted Security Solution</h2>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                <div className="bg-white p-6 rounded-lg shadow-sm border">
                  <h3 className="text-lg font-semibold text-gray-800 mb-3">Advanced Threat Detection</h3>
                  <p className="text-gray-600">
                    Our platform leverages multiple security engines to provide comprehensive threat detection, identifying malware, phishing attempts, and suspicious content that might otherwise go unnoticed.
                  </p>
                </div>
                
                <div className="bg-white p-6 rounded-lg shadow-sm border">
                  <h3 className="text-lg font-semibold text-gray-800 mb-3">Privacy First</h3>
                  <p className="text-gray-600">
                    We prioritize your privacy. While we scan files and URLs for threats, we don't store your sensitive data or share it with third parties. Your security is our primary concern.
                  </p>
                </div>
                
                <div className="bg-white p-6 rounded-lg shadow-sm border">
                  <h3 className="text-lg font-semibold text-gray-800 mb-3">Detailed Reports</h3>
                  <p className="text-gray-600">
                    Receive comprehensive reports that break down the scanning results, highlighting potential threats and providing actionable insights to help you make informed decisions.
                  </p>
                </div>
                
                <div className="bg-white p-6 rounded-lg shadow-sm border">
                  <h3 className="text-lg font-semibold text-gray-800 mb-3">User-Friendly Interface</h3>
                  <p className="text-gray-600">
                    Our intuitive interface makes it easy to scan files and URLs, view results, and understand potential threats. No technical expertise required to stay protected.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </div>
  );
};

export default HomePage;