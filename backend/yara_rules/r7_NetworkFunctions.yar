rule NetworkFunctions {
  meta:
    description = "Detects network communication functions"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "Network Activity"
  strings:
    $socket = "socket" wide
    $connect = "connect" wide
    $recv= "recv" wide
    $send = "send" wide
    $InternetOpen = "InternetOpen" wide
    $InternetConnect = "InternetConnect" wide
    $URLDownloadToFile = "URLDownloadToFile" wide
  condition:
    $socket or $connect or $recv or $send or $InternetOpen or $InternetConnect or $URLDownloadToFile
}
