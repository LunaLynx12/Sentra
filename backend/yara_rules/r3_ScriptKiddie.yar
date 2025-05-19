rule ScriptKiddie {
  meta:
    description = "Detects potential script kiddie tools"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "Tool"
  strings:
    $msfvenom = "msfvenom"
    $nmap = "nmap"
    $metasploit = "metasploit"
    $netcat = "netcat"
  condition:
    $msfvenom or $nmap or $metasploit or $netcat
}
