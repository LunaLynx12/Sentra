import React, { useEffect, useState } from 'react';
import { Check, AlertCircle, AlertTriangle, Shield, Loader2 } from 'lucide-react';
import { ThreatLevel } from '../../types';

interface ScanProgressProps {
  isScanning: boolean;
  threatLevel?: ThreatLevel;
  progress: number;
}

const ScanProgress: React.FC<ScanProgressProps> = ({ 
  isScanning, 
  threatLevel = 'unknown',
  progress
}) => {
  const [progressValue, setProgressValue] = useState(0);
  
  useEffect(() => {
    setProgressValue(progress);
  }, [progress]);
  
  const getStatusIcon = () => {
    if (isScanning) {
      return <Loader2 className="h-8 w-8 text-blue-600 animate-spin" />;
    }
    
    switch (threatLevel) {
      case 'safe':
        return <Check className="h-8 w-8 text-green-600" />;
      case 'suspicious':
      case 'phishing':  // Use same icon for phishing and suspicious
        return <AlertTriangle className="h-8 w-8 text-amber-500" />;
      case 'malicious':
        return <AlertCircle className="h-8 w-8 text-red-600" />;
      default:
        return <Shield className="h-8 w-8 text-gray-400" />;
    }
  };
  
  const getStatusText = () => {
    if (isScanning) {
      return 'Scanning...';
    }
    
    switch (threatLevel) {
      case 'safe':
        return 'No threats detected';
      case 'suspicious':
        return 'Suspicious content detected';
      case 'malicious':
        return 'Malicious content detected';
      case 'phishing':
        return 'Phishing attempt detected'
      default:
        return 'Unknown status';
    }
  };
  
  const getStatusColor = () => {
    if (isScanning) return 'bg-blue-600';
    
    switch (threatLevel) {
      case 'safe':
        return 'bg-green-600';
      case 'suspicious':
        return 'bg-amber-500';
      case 'malicious':
        return 'bg-red-600';
      case 'phishing':
        return 'bg-amber-500';
      default:
        return 'bg-gray-400';
    }
  };
  
  return (
    <div className="bg-white rounded-lg border p-6 w-full">
      <div className="flex flex-col items-center justify-center space-y-4">
        {isScanning ? (
          <>
            <div className="relative w-full h-3 bg-gray-200 rounded-full overflow-hidden">
              <div 
                className={`absolute top-0 left-0 h-full ${getStatusColor()} transition-all duration-300 ease-out`}
                style={{ width: `${progressValue}%` }}
              />
            </div>
            <p className="text-sm text-gray-500">Scanning with multiple engines...</p>
          </>
        ) : (
          <div className={`flex items-center justify-center w-16 h-16 rounded-full ${
            threatLevel === 'safe' ? 'bg-green-100' :
            threatLevel === 'suspicious' ? 'bg-amber-100' :
            threatLevel === 'malicious' ? 'bg-red-100' : 'bg-gray-100' 
          }`}>
            {getStatusIcon()}
          </div>
        )}
        
        <h3 className={`text-xl font-semibold ${
          threatLevel === 'safe' ? 'text-green-700' :
          threatLevel === 'suspicious' ? 'text-amber-700' :
          threatLevel === 'malicious' ? 'text-red-700' : 'text-gray-700'
        }`}>
          {getStatusText()}
        </h3>
        
        {!isScanning && threatLevel === 'safe' && (
          <p className="text-sm text-gray-600 text-center">
            The item has been analyzed by our security engines and no threats were found.
          </p>
        )}
        
        {!isScanning && threatLevel === 'suspicious' && (
          <p className="text-sm text-gray-600 text-center">
            Some suspicious behavior was detected. Proceed with caution.
          </p>
        )}
        
        {!isScanning && threatLevel === 'malicious' && (
          <p className="text-sm text-gray-600 text-center">
            Dangerous content detected! We recommend not to proceed with this item.
          </p>
        )}
      </div>
    </div>
  );
};

export default ScanProgress;