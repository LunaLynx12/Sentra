rule SuspiciousExtensions {
  meta:
    description = "Detects files with suspicious extensions"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "Generic Suspicious"
  strings:
    $exe= ".exe" wide
    $dll = ".dll" wide
    $vbs = ".vbs" wide
    $bat = ".bat" wide
    $ps1 = ".ps1" wide
    $jar = ".jar" wide
    $msi = ".msi" wide
  condition:
    $exe or $dll or $vbs or $bat or $ps1 or $jar or $msi
}
