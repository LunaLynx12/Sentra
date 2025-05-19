rule PowerShellDownloadCradle {
  meta:
    description = "Detects PowerShell download cradle"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "Download Cradle"
  strings:
    $powershell = "powershell"
    $Invoke_WebRequest = "Invoke-WebRequest"
    $DownloadFile = "DownloadFile"
    $WebClient = "WebClient"
  condition:
    $powershell and ($Invoke_WebRequest or $DownloadFile or $WebClient)
}
