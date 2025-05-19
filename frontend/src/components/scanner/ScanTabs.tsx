import React from 'react';
import { File, Link2 } from 'lucide-react';
import { ScanType } from '../../types';

interface ScanTabsProps {
  activeTab: ScanType;
  onTabChange: (tab: ScanType) => void;
  isScanning: boolean;
}

const ScanTabs: React.FC<ScanTabsProps> = ({ activeTab, onTabChange, isScanning }) => {
  return (
    <div className="flex border-b space-x-1">
      <button
        onClick={() => !isScanning && onTabChange('file')}
        className={`flex items-center space-x-2 px-4 py-3 border-b-2 transition-colors ${
          activeTab === 'file'
            ? 'border-blue-600 text-blue-700'
            : 'border-transparent text-gray-600 hover:text-gray-800'
        } ${isScanning ? 'opacity-50 cursor-not-allowed' : ''}`}
        disabled={isScanning}
      >
        <File className="h-5 w-5" />
        <span className="font-medium">Scan File</span>
      </button>
      
      <button
        onClick={() => !isScanning && onTabChange('url')}
        className={`flex items-center space-x-2 px-4 py-3 border-b-2 transition-colors ${
          activeTab === 'url'
            ? 'border-blue-600 text-blue-700'
            : 'border-transparent text-gray-600 hover:text-gray-800'
        } ${isScanning ? 'opacity-50 cursor-not-allowed' : ''}`}
        disabled={isScanning}
      >
        <Link2 className="h-5 w-5" />
        <span className="font-medium">Scan URL</span>
      </button>
    </div>
  );
};

export default ScanTabs;