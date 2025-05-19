rule FileDeletion {
  meta:
    description = "Detects file deletion"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "Destructive Behavior"
  strings:
    $DeleteFile = "DeleteFile" wide
    $unlink = "unlink"
    $del = "del "
    $erase = "erase "
  condition:
    $DeleteFile or $unlink or $del or $erase
}
