rule SelfDeletingExecutable {
  meta:
    description = "Detects self-deleting executables"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "Self-Destruct"
  strings:
    $string1 = "cmd.exe /c del "
    $selfdelete = "selfdelete"
    $string3 = "remove-item $MyInvocation.MyCommand.Path"
  condition:
    $string1 or $selfdelete or $string3
}
