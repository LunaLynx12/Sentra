rule NetworkActivity {
    meta:
        description = "Flags suspicious network connections"
    strings:
        $a = "http://malicious-site.com"
        $b = "C2 communication"
        $c = "remote access"
    condition:
        $a or $b or $c
}
