rule EncryptionRelatedStrings {
  meta:
    description = "Detects strings related to encryption"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "Possible Crypto"
  strings:
    $AES = "AES_"
    $RSA = "RSA_"
    $CryptEncrypt = "CryptEncrypt"
    $CryptDecrypt = "CryptDecrypt"
    $GetProcAddress = "GetProcAddress"
    $LoadLibrary = "LoadLibrary"
  condition:
    $AES or $RSA or $CryptEncrypt or $CryptDecrypt or $GetProcAddress and $LoadLibrary
}
