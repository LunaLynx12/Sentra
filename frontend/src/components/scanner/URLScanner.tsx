import React, { useState } from 'react';
import { Link2, SearchIcon } from 'lucide-react';

interface URLScannerProps {
  onScanUrl: (url: string) => void;
  isScanning: boolean;
}

const URLScanner: React.FC<URLScannerProps> = ({ onScanUrl, isScanning }) => {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');

  const validateUrl = (value: string) => {
    // Basic URL validation
    try {
      const parsedUrl = new URL(value);
      return parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:';
    } catch (err) {
      return false;
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }
    
    // Add http:// if missing
    let urlToCheck = url;
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      urlToCheck = 'http://' + url;
    }
    
    if (!validateUrl(urlToCheck)) {
      setError('Please enter a valid URL');
      return;
    }
    
    setError('');
    onScanUrl(urlToCheck);
  };

  return (
    <div className="w-full">
      <div className="bg-white rounded-lg border p-6">
        <div className="flex items-center space-x-3 mb-4">
          <div className="bg-green-100 p-2.5 rounded-lg">
            <Link2 className="h-6 w-6 text-green-600" />
          </div>
          <h3 className="font-medium text-lg text-gray-900">URL Scanner</h3>
        </div>
        
        <form onSubmit={handleSubmit}>
          <div className="relative">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL to scan (e.g., https://example.com)"
              className={`w-full px-4 py-3 pr-12 border ${
                error ? 'border-red-500' : 'border-gray-300'
              } rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all`}
              disabled={isScanning}
            />
            <div className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400">
              <SearchIcon className="h-5 w-5" />
            </div>
          </div>
          
          {error && (
            <p className="mt-2 text-sm text-red-600">{error}</p>
          )}
          
          <button
            type="submit"
            disabled={isScanning || !url.trim()}
            className={`w-full mt-4 px-4 py-2 bg-blue-600 text-white rounded-lg transition-colors ${
              isScanning || !url.trim() ? 'opacity-50 cursor-not-allowed' : 'hover:bg-blue-700'
            }`}
          >
            {isScanning ? 'Scanning...' : 'Scan URL'}
          </button>
        </form>
        
        <p className="text-xs text-gray-500 mt-4">
          URL scanning checks for phishing, malware, and suspicious content using multiple security engines.
        </p>
      </div>
    </div>
  );
};

export default URLScanner;