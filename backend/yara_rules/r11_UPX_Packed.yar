rule UPX_Packed {
  meta:
    description = "Detects UPX packed executables"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "Packed"
  strings:
    $upx0 = { 55 50 58 00 }
    $upx1 = { 55 50 58 21 }
    $upx2 = { 55 50 58 20 }
  condition:
    $upx0 or $upx1 or $upx2
}
