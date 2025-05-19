import React, { useState, useRef } from 'react';
import { FileUp, X, File, AlertTriangle } from 'lucide-react';

interface FileScannerProps {
  onScanFile: (file: File) => void;
  isScanning: boolean;
}

const FileScanner: React.FC<FileScannerProps> = ({ onScanFile, isScanning }) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files.length > 0) {
      setSelectedFile(event.target.files[0]);
    }
  };

  const handleDragOver = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(false);
    
    if (event.dataTransfer.files && event.dataTransfer.files.length > 0) {
      setSelectedFile(event.dataTransfer.files[0]);
    }
  };

  const handleClearFile = () => {
    setSelectedFile(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleStartScan = () => {
    if (selectedFile) {
      onScanFile(selectedFile);
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
  };

  return (
    <div className="w-full">
      {!selectedFile ? (
        <div
          className={`border-2 border-dashed rounded-lg p-8 text-center ${
            isDragging ? 'border-blue-500 bg-blue-50' : 'border-gray-300'
          } transition-colors duration-200`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          <div className="flex flex-col items-center justify-center space-y-4">
            <FileUp className="h-12 w-12 text-gray-400" />
            <div>
              <p className="text-lg font-medium text-gray-700">Drag and drop file here</p>
              <p className="text-sm text-gray-500 mt-1">or click to browse</p>
            </div>
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileSelect}
              className="hidden"
              id="file-upload"
            />
            <button
              onClick={() => fileInputRef.current?.click()}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              Select File
            </button>
            <p className="text-xs text-gray-500 mt-2">
              Supported file types: executables, documents, archives, images and more
            </p>
          </div>
        </div>
      ) : (
        <div className="bg-white rounded-lg border p-6">
          <div className="flex justify-between items-center mb-4">
            <div className="flex items-center space-x-3">
              <div className="bg-blue-100 p-2.5 rounded-lg">
                <File className="h-6 w-6 text-blue-600" />
              </div>
              <div className="truncate max-w-xs">
                <p className="font-medium text-gray-900 truncate">{selectedFile.name}</p>
                <p className="text-sm text-gray-500">{formatFileSize(selectedFile.size)}</p>
              </div>
            </div>
            {!isScanning && (
              <button
                onClick={handleClearFile}
                className="text-gray-500 hover:text-gray-700 transition-colors"
              >
                <X className="h-5 w-5" />
              </button>
            )}
          </div>
          
          {!isScanning && (
            <div className="mt-4">
              <div className="flex space-x-2 mb-4">
                <AlertTriangle className="text-amber-500 h-5 w-5" />
                <p className="text-xs text-gray-600">
                  Files are scanned using multiple antivirus engines. Don't upload sensitive data.
                </p>
              </div>
              <button
                onClick={handleStartScan}
                className="w-full px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                Scan File
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default FileScanner;