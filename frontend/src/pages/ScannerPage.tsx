import React, { useState, useEffect } from 'react';
import Header from '../components/Header';
import Footer from '../components/Footer';
import FileScanner from '../components/scanner/FileScanner';
import URLScanner from '../components/scanner/URLScanner';
import ScanTabs from '../components/scanner/ScanTabs';
import ScanProgress from '../components/scanner/ScanProgress';
import ResultDetails from '../components/results/ResultDetails';
import ScanHistory from '../components/results/ScanHistory';
import { ScanResult, ScanType, ScanStatus, ScanHistoryItem } from '../types';
import mockScan from '../utils/mockScan';

const ScannerPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ScanType>('file');
  const [scanStatus, setScanStatus] = useState<ScanStatus>('idle');
  const [scanProgress, setScanProgress] = useState(0);
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);
  
  // Function to handle file scanning
  const handleFileScan = async (file: File) => {
    setScanStatus('scanning');
    setScanProgress(0);
    
    // Simulate progress updates
    const progressInterval = setInterval(() => {
      setScanProgress(prev => {
        const newProgress = prev + Math.floor(Math.random() * 10) + 1;
        return newProgress > 95 ? 95 : newProgress;
      });
    }, 200);
    
    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch('http://localhost:8100/scan/', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) throw new Error('Scan failed');

      const result = await response.json();
      
      // Clear interval and set to 100% before showing results
      clearInterval(progressInterval);
      setScanProgress(100);
      
      // Short delay to show 100% before completing
      setTimeout(() => {
        setCurrentResult(result);
        setScanStatus('completed');
        
        // Add to scan history
        const historyItem: ScanHistoryItem = {
          id: result.id,
          type: result.type,
          name: result.name,
          timestamp: result.timestamp,
          threatLevel: result.threatLevel
        };

        console.log(result.threatLevel)
        
        setScanHistory(prev => [historyItem, ...prev.slice(0, 9)]);
      }, 500);
    } catch (error) {
      clearInterval(progressInterval);
      setScanStatus('error');
      console.error('Scan error:', error);
    }
  };
  
  // Function to handle URL scanning
  const handleUrlScan = async (url: string) => {
    setScanStatus('scanning');
    setScanProgress(0);
    
    // Simulate progress updates
    const progressInterval = setInterval(() => {
      setScanProgress(prev => {
        const newProgress = prev + Math.floor(Math.random() * 10) + 1;
        return newProgress > 95 ? 95 : newProgress;
      });
    }, 200);
    
    try {
      const response = await fetch('http://localhost:8100/scan/url/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }), // Sending URL as JSON payload
      });

      if (!response.ok) throw new Error('Scan failed');

      const result = await response.json();
      
      // Clear interval and set to 100% before showing results
      clearInterval(progressInterval);
      setScanProgress(100);
      
      // Short delay to show 100% before completing
      setTimeout(() => {
        // Update the result with the name and other relevant fields
        setCurrentResult({
          id: `url-${Date.now()}`, // Generate a unique ID if not provided
          type: result.type || 'url',
          name: result.name || url, // Use the URL if name isn't provided
          timestamp: new Date().toISOString(),
          threatLevel: result.threatLevel?.toLowerCase() || 'unknown', // Ensure lowercase
          filetype: 'URL', // Added for consistency with file scans
          hashes: {}, // Empty for URLs
          detectionRatio: {
            detected: result.threatLevel === 'phishing' ? 1 : 0,
            total: 1
          },
          detections: result.analysis ? [{
            engine: 'Gemini AI',
            result: result.analysis
          }] : [],
          analysis: result.analysis // Include the full analysis
        });
      console.log(result.analysis)

      setScanStatus('completed');

      // Add to scan history
      const historyItem: ScanHistoryItem = {
        id: `url-${Date.now()}`,
        type: result.type || 'url',
        name: result.name || url,
        timestamp: new Date().toISOString(),
        threatLevel: result.threatLevel?.toLowerCase() || 'unknown'
      };

      setScanHistory((prev) => [historyItem, ...prev.slice(0, 9)]);
      }, 500);
    } catch (error) {
      clearInterval(progressInterval);
      setScanStatus('error');
      console.error('Scan error:', error);
    }
  };
  
  // Function to handle selecting an item from history
  const handleSelectHistoryItem = (id: string) => {
    // In a real application, we would fetch the detailed result from an API
    // For this demo, we'll just use the current result if it matches the ID
    if (currentResult && currentResult.id === id) {
      // It's already the current result
      return;
    }
    
    // Otherwise, simulate fetching the result
    setScanStatus('scanning');
    
    setTimeout(() => {
      // Find the history item
      const historyItem = scanHistory.find(item => item.id === id);
      
      if (historyItem) {
        // Create a mock result based on the history item
        const mockResult: ScanResult = {
          ...historyItem,
          detectionRatio: {
            detected: Math.floor(Math.random() * 5),
            total: 15
          },
          detections: Array.from({ length: 15 }).map((_, i) => ({
            engine: `Engine${i + 1}`,
            result: Math.random() > 0.7 ? null : 'Suspicious'
          }))
        };
        
        setCurrentResult(mockResult);
        setScanStatus('completed');
      }
    }, 1000);
  };
  
  // Reset when changing tabs
  useEffect(() => {
    if (scanStatus !== 'scanning') {
      setScanStatus('idle');
      setCurrentResult(null);
    }
  }, [activeTab]);
  
  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      <Header />
      <main className="flex-grow pt-16">
        <div className="container mx-auto px-4 py-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-6">Security Scanner</h1>
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2">
              <div className="bg-white rounded-lg border shadow-sm">
                <ScanTabs 
                  activeTab={activeTab} 
                  onTabChange={setActiveTab} 
                  isScanning={scanStatus === 'scanning'} 
                />
                
                <div className="p-6">
                  {activeTab === 'file' ? (
                    <FileScanner 
                      onScanFile={handleFileScan} 
                      isScanning={scanStatus === 'scanning'} 
                    />
                  ) : (
                    <URLScanner 
                      onScanUrl={handleUrlScan} 
                      isScanning={scanStatus === 'scanning'} 
                    />
                  )}
                  
                  {(scanStatus === 'scanning' || scanStatus === 'completed') && (
                    <div className="mt-8">
                      <ScanProgress 
                        isScanning={scanStatus === 'scanning'} 
                        threatLevel={currentResult?.threatLevel} 
                        progress={scanProgress} 
                      />
                    </div>
                  )}
                </div>
              </div>
              
              {currentResult && scanStatus === 'completed' && (
                <div className="mt-8">
                  <ResultDetails result={currentResult} />
                </div>
              )}
            </div>
            
            <div>
              <ScanHistory 
                history={scanHistory} 
                onSelectItem={handleSelectHistoryItem} 
              />
              
              <div className="bg-blue-50 rounded-lg border border-blue-200 mt-6 p-6">
                <h3 className="text-lg font-semibold text-blue-800 mb-3">Scanning Tips</h3>
                <ul className="space-y-2 text-sm text-blue-700">
                  <li>• Files are scanned using multiple security engines</li>
                  <li>• URL scanning checks for phishing and malware</li>
                  <li>• Results are color-coded for easy understanding</li>
                  <li>• Use caution with files marked as suspicious</li>
                  <li>• Never open files marked as malicious</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </main>
      <Footer />
    </div>
  );
};

export default ScannerPage;