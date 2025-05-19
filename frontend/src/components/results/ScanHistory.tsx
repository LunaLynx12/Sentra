import React from 'react';
import { ScanHistoryItem, ThreatLevel } from '../../types';
import { Shield, AlertTriangle, AlertCircle, FileText, Link2 } from 'lucide-react';

interface ScanHistoryProps {
  history: ScanHistoryItem[];
  onSelectItem: (id: string) => void;
}

const ScanHistory: React.FC<ScanHistoryProps> = ({ history, onSelectItem }) => {
  const getIcon = (type: 'file' | 'url', threatLevel: ThreatLevel) => {
    if (type === 'file') {
      return <FileText className="h-5 w-5 text-blue-600" />;
    } else {
      return <Link2 className="h-5 w-5 text-blue-600" />;
    }
  };
  
  const getThreatIcon = (threatLevel: ThreatLevel) => {
    switch (threatLevel) {
      case 'safe':
        return <Shield className="h-4 w-4 text-green-600" />;
      case 'suspicious':
        return <AlertTriangle className="h-4 w-4 text-amber-500" />;
      case 'malicious':
        return <AlertCircle className="h-4 w-4 text-red-600" />;
      default:
        return <Shield className="h-4 w-4 text-gray-500" />;
    }
  };
  
  if (history.length === 0) {
    return (
      <div className="bg-white rounded-lg border p-6">
        <p className="text-gray-500 text-center">No scan history available</p>
      </div>
    );
  }
  
  return (
    <div className="bg-white rounded-lg border shadow-sm">
      <div className="p-4 border-b">
        <h2 className="text-lg font-semibold text-gray-800">Recent Scans</h2>
      </div>
      <div className="divide-y">
        {history.map((item) => (
          <button
            key={item.id}
            onClick={() => onSelectItem(item.id)}
            className="w-full p-4 hover:bg-gray-50 transition-colors flex items-center justify-between text-left"
          >
            <div className="flex items-center space-x-3">
              {getIcon(item.type, item.threatLevel)}
              <div>
                <p className="font-medium text-gray-900 truncate max-w-xs">{item.name}</p>
                <p className="text-sm text-gray-500">{item.type} scan</p>
              </div>
            </div>
            <div className="flex items-center space-x-1">
              {getThreatIcon(item.threatLevel)}
              <span className={`text-xs font-medium capitalize ${
                item.threatLevel === 'safe' ? 'text-green-600' :
                item.threatLevel === 'suspicious' ? 'text-amber-500' :
                item.threatLevel === 'malicious' ? 'text-red-600' : 'text-gray-500'
              }`}>
                {item.threatLevel}
              </span>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
};

export default ScanHistory;