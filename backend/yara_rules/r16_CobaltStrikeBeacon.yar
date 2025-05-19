rule CobaltStrikeBeacon {
  meta:
    description = "Detects Cobalt Strike Beacon"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "C2 Beacon"
  strings:
    $MZ = "MZ"
    $stage = "stage"
    $Cobalt_Strike = "Cobalt Strike"
  condition:
    $MZ and $stage and $Cobalt_Strike 
}

