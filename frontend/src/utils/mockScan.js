const engineNames = [
  'AntiVir', 'Avast', 'BitDefender', 'ClamAV', 'Kaspersky',
  'Malwarebytes', 'McAfee', 'Norton', 'Panda', 'Sophos',
  'Symantec', 'TrendMicro', 'ESET', 'F-Secure', 'Webroot'
];

const detectionTypes = {
  malicious: ['Trojan', 'Virus', 'Worm', 'Ransomware', 'Spyware', 'Backdoor', 'Rootkit'],
  suspicious: ['PUA', 'Suspicious', 'Riskware', 'Adware', 'Heuristic.Suspicious'],
  safe: [null]
};

const mockScan = (input, type) => {
  return new Promise((resolve) => {
    // Random scan duration between 2-5 seconds
    const scanDuration = Math.floor(Math.random() * 3000) + 2000;
    
    setTimeout(() => {
      // Randomly determine threat level (weighted)
      const rand = Math.random();
      let threatLevel;
      
      if (rand < 0.7) {
        threatLevel = 'safe';
      } else if (rand < 0.85) {
        threatLevel = 'suspicious';
      } else if (rand < 0.95) {
        threatLevel = 'malicious';
      } else {
        threatLevel = 'unknown';
      }
      
      // Generate random detections based on threat level
      const totalEngines = Math.floor(Math.random() * 5) + 10; // Between 10-15 engines
      let detectedCount = 0;
      
      const detections = Array.from({ length: totalEngines }).map((_, i) => {
        const engine = engineNames[i % engineNames.length];
        let result = null;
        
        if (threatLevel === 'malicious') {
          // 70-90% of engines detect it
          if (Math.random() < 0.8) {
            result = detectionTypes.malicious[Math.floor(Math.random() * detectionTypes.malicious.length)];
            detectedCount++;
          }
        } else if (threatLevel === 'suspicious') {
          // 20-40% of engines detect it
          if (Math.random() < 0.3) {
            result = detectionTypes.suspicious[Math.floor(Math.random() * detectionTypes.suspicious.length)];
            detectedCount++;
          }
        } else if (threatLevel === 'unknown') {
          // 5-15% of engines detect it
          if (Math.random() < 0.1) {
            result = detectionTypes.suspicious[Math.floor(Math.random() * detectionTypes.suspicious.length)];
            detectedCount++;
          }
        }
        
        return {
          engine,
          result
        };
      });
      
      // Generate file size if it's a file scan (between 10KB and 50MB)
      const size = type === 'file' ? Math.floor(Math.random() * 50000) + 10 : undefined;
      
      resolve({
        id: Math.random().toString(36).substring(2, 15),
        type,
        name: input,
        size,
        timestamp: new Date(),
        threatLevel,
        detectionRatio: {
          detected: detectedCount,
          total: totalEngines
        },
        detections,
        metadata: {
          scannedWith: 'VirusTotal Lite',
          scanVersion: '1.0.0'
        }
      });
    }, scanDuration);
  });
};

export default mockScan;