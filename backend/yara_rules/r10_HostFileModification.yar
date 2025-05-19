rule HostFileModification {
  meta:
    description = "Detects attempts to modify host file"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "Host File Manipulation"
  strings:
    $host_file_path = "C:\\Windows\\System32\\drivers\\etc\\hosts" wide
    $string1 = "127.0.0.1"
  condition:
    $host_file_path and $string1
}
