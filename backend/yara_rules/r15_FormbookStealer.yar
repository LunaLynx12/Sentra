rule FormbookStealer {
  meta:
    description = "Detects Formbook Stealer"
    author = "Your Name"
    date = "2024-07-24"
    malware_type = "Stealer"
  strings:
    $FormBook = "FormBook"
    $http_client = "http.client"
    $multipart_form_data = "multipart/form-data"
  condition:
    $FormBook and $http_client and $multipart_form_data 
}
