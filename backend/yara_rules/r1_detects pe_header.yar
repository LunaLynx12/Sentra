rule PEFile {
  meta:
    description = "Detects Portable Executable (PE) file header"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "Generic PE"
  strings:
    $mz = { 4D 5A }
    $pe = { 50 45 00 00 }
  condition:
    $mz at 0 and $pe at 0x3c
}
