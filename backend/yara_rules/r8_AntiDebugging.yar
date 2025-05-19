rule AntiDebugging {
  meta:
    description = "Detects anti-debugging techniques"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "Anti-Analysis"
  strings:
    $IsDebuggerPresent = "IsDebuggerPresent" wide
    $CheckRemoteDebuggerPresent = "CheckRemoteDebuggerPresent" wide
    $OutputDebugString = "OutputDebugString" wide
  condition:
    $IsDebuggerPresent or $CheckRemoteDebuggerPresent or $OutputDebugString 
}
