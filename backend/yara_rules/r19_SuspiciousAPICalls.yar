rule SuspiciousAPICalls {
  meta:
    description = "Detects suspicious API calls"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "Suspicious Activity"
  strings:
    $CreateProcess = "CreateProcess"
    $WriteProcessMemory = "WriteProcessMemory"
    $CreateThread = "CreateThread"
    $LoadLibraryA = "LoadLibraryA"
    $GetProcAddress = "GetProcAddress"
  condition:
    $CreateProcess and $WriteProcessMemory and $CreateThread and $LoadLibraryA and $GetProcAddress 
}
