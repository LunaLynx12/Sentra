rule AutostartRegistry {
  meta:
    description = "Detects autostart registry keys (Windows)"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "Persistence"
  strings:
    $HKLM_Software_Microsoft_Windows_CurrentVersion_Run = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
    $HKCU_Software_Microsoft_Windows_CurrentVersion_Run = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
  condition:
    $HKLM_Software_Microsoft_Windows_CurrentVersion_Run or $HKCU_Software_Microsoft_Windows_CurrentVersion_Run
}
