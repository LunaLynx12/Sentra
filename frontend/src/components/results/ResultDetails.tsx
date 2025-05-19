import React, { useState } from 'react';
import {
  Shield,
  AlertTriangle,
  AlertCircle,
  Activity,
  Calendar,
  FileText,
  Link2,
  X,
  ClipboardCopy,
} from 'lucide-react';

interface ScanResult {
  id: string;
  name: string;
  type: 'file' | 'url';
  timestamp: string;
  filetype?: string;
  threatLevel: 'high' | 'low' | 'medium' | 'unknown';
  hashes: {
    md5: string;
    sha1: string;
    sha256: string;
    sha512: string;
    sha3_256: string;
    blake2b: string;
    blake2s: string;
  };
  detectionRatio: {
    detected: number;
    total: number;
  };
  detections?: Array<{
    rule?: string;
    tags?: string[];
    meta?: Record<string, string>;
    strings?: Array<{
      identifier: string;
      offset: number;
      data: string;
    }>;
    engine?: string;
    result?: string;
  }>;
  pe_analysis?: {
    machine: number;
    compile_time: number;
    entry_point: number;
    image_base: number;
    subsystem: number;
    dll_characteristics: number;
    sections: Array<{
      name: string;
      virtual_address: string;
      virtual_size: string;
      raw_size: string;
      entropy: number;
      characteristics: string;
    }>;
    imports: Record<string, string[]>;
    exports: string[];
    resources: Array<{
      type: string;
      size: number;
      sha256: string;
    }>;
    is_dll: boolean;
    is_exe: boolean;
    is_driver: boolean;
    packer: string;
  };
  pdf_analysis?: {
    findings: Array<{
      page: number;
      reasons: string[];
      text: string;
      font_size: number;
      color: string;
    }>;
    sample_text: string;
  };
  image_analysis?: {
    findings: string[];
    file_format?: string;
    dimensions?: string;
    megapixels?: number;
    device_make?: string | null;
    device_model?: string | null;
    software?: string | null;
    datetime?: string | null;
    exe_detection?: string;
    jpeg_comment?: string;
  };
}

interface ResultDetailsProps {
  result: ScanResult;
}

const formatDate = (dateString?: string): string => {
  if (!dateString) return 'N/A';
  const date = new Date(dateString);
  return date.toLocaleString();
};

const formatFileSize = (bytes?: number): string => {
  if (!bytes) return 'N/A';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
};

const ResultDetails: React.FC<ResultDetailsProps> = ({ result }) => {
  const [showSizeError, setShowSizeError] = useState(false);

  React.useEffect(() => {
    if (result.detail?.includes("This file exceeds the 25")) {
      setShowSizeError(true);
    }
  }, []);

  const threatColors = {
    high: 'text-red-600',
    medium: 'text-amber-500',
    low: 'text-green-600',
    unknown: 'text-gray-500',
  };

  const threatBgColors = {
    high: 'bg-red-100',
    medium: 'bg-amber-100',
    low: 'bg-green-100',
    unknown: 'bg-gray-100',
  };

  const threatIcons = {
    high: <AlertCircle className="h-5 w-5 text-red-600" />,
    medium: <AlertTriangle className="h-5 w-5 text-amber-500" />,
    low: <Shield className="h-5 w-5 text-green-600" />,
    unknown: <Shield className="h-5 w-5 text-gray-500" />,
  };

  const detectionPercentage = result.detectionRatio
    ? Math.round((result.detectionRatio.detected / result.detectionRatio.total) * 100)
    : 0;

  // Format time from compile_time (seconds since epoch)
  const peCompileTime =
    result.pe_analysis && new Date(result.pe_analysis.compile_time * 1000).toLocaleString();

  return (
    <div className="bg-white rounded-lg border shadow-sm">
      {/* Header */}
      <div className="p-6 border-b">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-gray-800">Scan Results</h2>
          <div
            className={`px-3 py-1 rounded-full ${threatBgColors[result.threatLevel]} flex items-center space-x-1`}
          >
            {threatIcons[result.threatLevel]}
            <span
              className={`text-sm font-medium ${threatColors[result.threatLevel]} capitalize`}
            >
              {result.threatLevel}
            </span>
          </div>
        </div>

        {/* File/URL Info */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="flex items-start space-x-3">
            {result.type === 'file' ? (
              <FileText className="h-5 w-5 text-blue-600 mt-0.5" />
            ) : (
              <Link2 className="h-5 w-5 text-blue-600 mt-0.5" />
            )}
            <div>
              <p className="text-sm text-gray-500">Name</p>
              <p className="font-medium text-gray-900 break-all">{result.name}</p>
            </div>
          </div>
          <div className="flex items-start space-x-3">
            <Calendar className="h-5 w-5 text-blue-600 mt-0.5" />
            <div>
              <p className="text-sm text-gray-500">Scan Date</p>
              <p className="font-medium text-gray-900">{formatDate(result.timestamp)}</p>
            </div>
          </div>
          {result.type === 'file' && result.filetype && (
            <div className="flex items-start space-x-3">
              <FileText className="h-5 w-5 text-blue-600 mt-0.5" />
              <div>
                <p className="text-sm text-gray-500">File Type</p>
                <p className="font-medium text-gray-900">{result.filetype}</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Hashes Section */}
      {result.hashes && Object.keys(result.hashes).length > 0 && (
        <div className="p-6 border-t">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-800">Hashes</h3>
            <button
              onClick={() =>
                navigator.clipboard.writeText(JSON.stringify(result.hashes, null, 2))
              }
              className="text-sm text-blue-600 hover:text-blue-800 flex items-center"
            >
              <ClipboardCopy className="w-4 h-4 mr-1" />
              Copy All
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {Object.entries(result.hashes).map(([hashType, hashValue]) => (
              <div
                key={hashType}
                className="bg-gray-50 rounded-lg p-3 hover:bg-gray-100 transition-colors"
              >
                <div className="flex justify-between items-start">
                  <p className="text-xs font-medium text-gray-500 uppercase tracking-wider">
                    {hashType}
                  </p>
                  <button
                    onClick={() => navigator.clipboard.writeText(hashValue)}
                    className="text-gray-400 hover:text-gray-600"
                    title="Copy hash"
                  >
                    <ClipboardCopy className="w-3 h-3" />
                  </button>
                </div>
                <div className="mt-1">
                  <p className="font-mono text-sm text-gray-800 break-all">{hashValue}</p>
                </div>
                {hashType === 'sha256' && (
                  <div className="mt-2 flex space-x-2">
                    <a
                      href={`https://www.virustotal.com/gui/search/ ${encodeURIComponent(
                        hashValue
                      )}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-blue-600 hover:underline"
                    >
                      Check on VirusTotal
                    </a>
                    <a
                      href={`https://www.hybrid-analysis.com/search?query= ${encodeURIComponent(
                        hashValue
                      )}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-blue-600 hover:underline"
                    >
                      Check on Hybrid Analysis
                    </a>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {result.pdf_analysis && (
        <div className="p-6 border-t">
          <h3 className="text-lg font-semibold text-gray-800 mb-4">PDF Analysis</h3>

          {/* Summary Info */}
          <div className="mb-4">
            <p className="text-sm text-gray-500">Hidden or Small Text Detected:</p>
            <p className="font-medium text-red-600">{result.pdf_analysis.findings.length} finding(s)</p>
          </div>

          {/* Findings Table */}
          {result.pdf_analysis.findings.length > 0 && (
            <>
              <h4 className="text-md font-semibold text-gray-700 mb-2">Detected Issues</h4>
              <div className="overflow-x-auto mb-6">
                <table className="min-w-full table-auto divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-4 py-2 text-left text-sm font-medium text-gray-500">Page</th>
                      <th className="px-4 py-2 text-left text-sm font-medium text-gray-500">Reason</th>
                      <th className="px-4 py-2 text-left text-sm font-medium text-gray-500">Text Snippet</th>
                      <th className="px-4 py-2 text-left text-sm font-medium text-gray-500">Font Size</th>
                      <th className="px-4 py-2 text-left text-sm font-medium text-gray-500">Color</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {result.pdf_analysis.findings.map((finding, idx) => (
                      <tr key={idx}>
                        <td className="px-4 py-2 text-sm text-gray-800">{finding.page}</td>
                        <td className="px-4 py-2 text-sm text-gray-800">
                          {finding.reasons.join(", ")}
                        </td>
                        <td className="px-4 py-2 text-sm text-gray-800 max-w-xs truncate">
                          "{finding.text}"
                        </td>
                        <td className="px-4 py-2 text-sm text-gray-800">{finding.font_size}</td>
                        <td className="px-4 py-2 text-sm text-gray-800 flex items-center">
                          <span
                            className="inline-block w-4 h-4 mr-2 rounded-full"
                            style={{ backgroundColor: finding.color }}
                          ></span>
                          {finding.color}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {/* Full Text Preview */}
          <div>
            <h4 className="text-md font-semibold text-gray-700 mb-2">Extracted Text</h4>
            <div className="bg-gray-50 p-4 rounded-lg text-sm whitespace-pre-wrap font-mono max-h-96 overflow-y-auto">
              {result.pdf_analysis.sample_text}
            </div>
          </div>
        </div>
      )}

      {/* IMAGE ANALYSIS SECTION */}
        {result.image_analysis && (
          <div className="p-6 border-t">
            <h3 className="text-lg font-semibold text-gray-800 mb-4">Image Analysis</h3>

            {/* Summary Info */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
              <div>
                <p className="text-sm text-gray-500">File Format</p>
                <p className="font-medium text-gray-900">{result.image_analysis.file_format || 'Unknown'}</p>
              </div>
              <div>
                <p className="text-sm text-gray-500">Dimensions</p>
                <p className="font-medium text-gray-900">{result.image_analysis.dimensions || 'Unknown'}</p>
              </div>
              <div>
                <p className="text-sm text-gray-500">Megapixels</p>
                <p className="font-medium text-gray-900">{result.image_analysis.megapixels?.toFixed(2) || '0'} MP</p>
              </div>
              <div>
                <p className="text-sm text-gray-500">Embedded EXE?</p>
                <p className="font-medium text-gray-900">{result.image_analysis.exe_detection || 'No'}</p>
              </div>
            </div>

            {/* Findings */}
            {Array.isArray(result.image_analysis.findings) && result.image_analysis.findings.length > 0 && (
              <>
                <h4 className="text-md font-semibold text-gray-700 mb-2">Security Findings</h4>
                <ul className="list-disc pl-5 mb-6">
                  {result.image_analysis.findings.map((finding, idx) => (
                    <li key={idx} className="text-sm text-red-600 font-medium">
                      {finding}
                    </li>
                  ))}
                </ul>
              </>
            )}

            {/* JPEG Comment */}
            {result.image_analysis.jpeg_comment && (
              <div className="mb-6">
                <h4 className="text-md font-semibold text-gray-700 mb-2">JPEG Comment</h4>
                <div className="bg-gray-50 p-4 rounded-lg font-mono text-sm break-all">
                  {result.image_analysis.jpeg_comment}
                </div>
              </div>
            )}

            {/* EXIF Metadata */}
            {(result.image_analysis.device_make ||
              result.image_analysis.device_model ||
              result.image_analysis.software ||
              result.image_analysis.datetime) && (
              <div className="mb-6">
                <h4 className="text-md font-semibold text-gray-700 mb-2">EXIF Metadata</h4>
                <ul className="space-y-1">
                  {result.image_analysis.device_make && (
                    <li className="text-sm">
                      <span className="font-medium">Device Make:</span> {result.image_analysis.device_make}
                    </li>
                  )}
                  {result.image_analysis.device_model && (
                    <li className="text-sm">
                      <span className="font-medium">Device Model:</span> {result.image_analysis.device_model}
                    </li>
                  )}
                  {result.image_analysis.software && (
                    <li className="text-sm">
                      <span className="font-medium">Software Used:</span> {result.image_analysis.software}
                    </li>
                  )}
                  {result.image_analysis.datetime && (
                    <li className="text-sm">
                      <span className="font-medium">Date & Time:</span> {result.image_analysis.datetime}
                    </li>
                  )}
                </ul>
              </div>
            )}
          </div>
        )}

      {/* PE Analysis Section */}
      {result.pe_analysis && (
        <div className="p-6 border-t">
          <h3 className="text-lg font-semibold text-gray-800 mb-4">PE File Analysis</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            {result.pe_analysis.machine === 34404 && (
              <div>
                <p className="text-sm text-gray-500">Machine</p>
                <p className="font-medium text-gray-900">AMD64</p>
              </div>
            )}
            <div>
              <p className="text-sm text-gray-500">Compile Time</p>
              <p className="font-medium text-gray-900">{peCompileTime}</p>
            </div>
            <div>
              <p className="text-sm text-gray-500">Entry Point</p>
              <p className="font-medium text-gray-900">
                {result.pe_analysis.entry_point.toString(16)}
              </p>
            </div>
            <div>
              <p className="text-sm text-gray-500">Image Base</p>
              <p className="font-medium text-gray-900">
                {result.pe_analysis.image_base.toString(16)}
              </p>
            </div>
            <div>
              <p className="text-sm text-gray-500">Packer Detected</p>
              <p className="font-medium text-gray-900">
                {result.pe_analysis.packer || 'None'}
              </p>
            </div>
          </div>

          {/* Sections */}
          <div className="mb-6">
            <h4 className="text-md font-semibold text-gray-700 mb-2">Sections</h4>
            <div className="overflow-x-auto">
              <table className="min-w-full table-auto divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-2 text-left text-sm font-medium text-gray-500">
                      Name
                    </th>
                    <th className="px-4 py-2 text-left text-sm font-medium text-gray-500">
                      Virtual Address
                    </th>
                    <th className="px-4 py-2 text-left text-sm font-medium text-gray-500">
                      Size
                    </th>
                    <th className="px-4 py-2 text-left text-sm font-medium text-gray-500">
                      Entropy
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {result.pe_analysis.sections.map((sec, idx) => (
                    <tr key={idx}>
                      <td className="px-4 py-2 text-sm text-gray-800">{sec.name}</td>
                      <td className="px-4 py-2 text-sm text-gray-800">
                        {sec.virtual_address}
                      </td>
                      <td className="px-4 py-2 text-sm text-gray-800">
                        {parseInt(sec.virtual_size, 16)} bytes
                      </td>
                      <td className="px-4 py-2 text-sm text-gray-800">
                        {sec.entropy.toFixed(2)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Imports */}
          <div className="mb-6">
            <h4 className="text-md font-semibold text-gray-700 mb-2">Imports</h4>
            <div className="space-y-2">
              {Object.entries(result.pe_analysis.imports).map(([dll, funcs], index) => (
                <div key={index} className="border rounded p-2 bg-gray-50">
                  <strong>{dll}</strong>
                  <ul className="list-disc ml-5 mt-1 text-sm">
                    {funcs.map((func, i) => (
                      <li key={i}>{func}</li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>

          {/* Exports */}
          <div className="mb-6">
            <h4 className="text-md font-semibold text-gray-700 mb-2">Exports</h4>
            <ul className="list-disc ml-5">
              {result.pe_analysis.exports.map((exp, idx) => (
                <li key={idx} className="text-sm">
                  {exp}
                </li>
              ))}
            </ul>
          </div>

          {/* Resources */}
          <div>
            <h4 className="text-md font-semibold text-gray-700 mb-2">Resources</h4>
            <div className="overflow-x-auto">
              <table className="min-w-full table-auto divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-2 text-left text-sm font-medium text-gray-500">
                      Type
                    </th>
                    <th className="px-4 py-2 text-left text-sm font-medium text-gray-500">
                      Size
                    </th>
                    <th className="px-4 py-2 text-left text-sm font-medium text-gray-500">
                      SHA256
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {result.pe_analysis.resources.map((res, idx) => (
                    <tr key={idx}>
                      <td className="px-4 py-2 text-sm text-gray-800">{res.type}</td>
                      <td className="px-4 py-2 text-sm text-gray-800">{res.size} bytes</td>
                      <td className="px-4 py-2 text-sm text-gray-800 font-mono">
                        {res.sha256}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Detection Details */}
      {result.detections && result.detections.length > 0 && (
        <div className="p-6 border-t">
          <h3 className="text-lg font-semibold text-gray-800 mb-4">Detection Details</h3>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Engine/Rule
                  </th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Details
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {result.detections.map((detection, index) => (
                  <tr key={index} className={index % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                      {detection.engine || detection.rule || 'Unknown'}
                    </td>
                    <td className="px-6 py-4 text-sm">
                      {detection.meta?.description ? (
                        <div>
                          <p className="text-red-600 font-medium">{detection.meta.description}</p>
                          {detection.strings && (
                            <div className="mt-2">
                              <p className="text-xs text-gray-500">Matched strings:</p>
                              <ul className="list-disc pl-5">
                                {detection.strings.map((str, i) => (
                                  <li key={i} className="font-mono text-xs">
                                    {str.identifier}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      ) : (
                        <span className={detection.result ? 'text-red-600' : 'text-green-600'}>
                          {detection.result || 'Clean'}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Size Limit Modal */}
      {showSizeError && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg shadow-xl max-w-md w-full p-6 relative">
            <button
              onClick={() => setShowSizeError(false)}
              className="absolute top-4 right-4 text-gray-400 hover:text-gray-600"
            >
              <X className="h-5 w-5" />
            </button>
            <div className="flex items-start">
              <div className="flex-shrink-0">
                <AlertTriangle className="h-6 w-6 text-yellow-500" />
              </div>
              <div className="ml-4">
                <h3 className="text-lg font-medium text-gray-900">File Size Limit Exceeded</h3>
                <div className="mt-2">
                  <p className="text-sm text-gray-600">
                    This file exceeds the 25 MB limit for guest users.
                  </p>
                  <p className="text-sm text-gray-600 mt-2">
                    To upload larger files, please consider upgrading to Pro.
                  </p>
                </div>
                <div className="mt-4 flex space-x-3">
                  <button
                    type="button"
                    className="inline-flex justify-center rounded-md border border-transparent bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
                    onClick={() => setShowSizeError(false)}
                  >
                    Understood
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ResultDetails;