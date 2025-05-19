rule DNSTunneling {
  meta:
    description = "Detects potential DNS tunneling"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "DNS Tunnel"
  strings:
    $nslookup = "nslookup"
    $dig = "dig "
    $domain = "domain="
  condition:
    $nslookup or $dig and $domain 
}
