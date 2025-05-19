rule CodeInjection {
  meta:
    description = "Detects code injection"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "Code Injection"
  strings:
    $WriteProcessMemory = "WriteProcessMemory" wide
    $CreateRemoteThread = "CreateRemoteThread" wide
    $VirtualAllocEx = "VirtualAllocEx" wide
  condition:
    $WriteProcessMemory and $CreateRemoteThread and $VirtualAllocEx
}
