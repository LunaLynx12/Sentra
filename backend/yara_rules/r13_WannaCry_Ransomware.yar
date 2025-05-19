rule WannaCry_Ransomware {
  meta:
    description = "Detects WannaCry Ransomware"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "Ransomware"
  strings:
    $string1 = "WannaCryptor"
    $string2 = "wnry"
    $string3 = "@WanaDecryptor@"
  condition:
    $string1 and $string2 and $string3
}
