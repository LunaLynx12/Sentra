rule SuspiciousBehavior {
    meta:
        description = "Detects patterns related to suspicious activity"
    strings:
        $keylogger = "keylogger"
        $exploit = "exploit"
        $obfuscation = "obfuscation"
    condition:
        $keylogger or $exploit or $obfuscation
}
