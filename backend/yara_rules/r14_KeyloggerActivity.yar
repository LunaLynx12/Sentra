rule KeyloggerActivity {
  meta:
    description = "Detects potential keylogger activity"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "Keylogger"
  strings:
    $GetKeyState = "GetKeyState"
    $GetAsyncKeyState = "GetAsyncKeyState"
    $RegisterRawInputDevices = "RegisterRawInputDevices"
  condition:
    $GetKeyState or $GetAsyncKeyState or $RegisterRawInputDevices 
}
