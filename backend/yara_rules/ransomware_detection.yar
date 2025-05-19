rule RansomwareDetection {
    meta:
        description = "Detects known ransomware-related patterns"
    strings:
        $encrypted = ".encrypted"
        $Bitcoin_ransom = "Bitcoin ransom"
        $decrypt_instructions = "decrypt instructions"
    condition:
        $encrypted or $Bitcoin_ransom or $decrypt_instructions 
}
