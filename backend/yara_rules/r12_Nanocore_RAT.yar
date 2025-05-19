rule Nanocore_RAT {
  meta:
    description = "Detects Nanocore Remote Administration Tool"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "RAT"
  strings:
    $Nanocore = "Nanocore"
    $Connection_Start = "Connection.Start"
    $Client_Networking_TCP = "Client.Networking.TCP"
  condition:
    $Nanocore and $Connection_Start and $Client_Networking_TCP
}
