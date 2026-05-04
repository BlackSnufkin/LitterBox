rule Windows_Trojan_MassLogger_511b001e {
    meta:
        author = "Elastic Security"
        id = "511b001e-dc67-4e45-9096-0b01101ca0ab"
        fingerprint = "14ec9c32af7c1dd4a1f73e37ef9e042c18d9e0179b0e5732752767f93be6d4e2"
        creation_date = "2022-03-02"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.MassLogger"
        reference_sample = "177875c756a494872c516000beb6011cec22bd9a73e58ba6b2371dba2ab8c337"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "ExecutionPolicy Bypass -WindowStyle Hidden -Command netsh advfirewall firewall add rule name='allow RemoteDesktop' dir=in protoc" wide
        $a2 = "https://raw.githubusercontent.com/lisence-system/assemply/main/VMprotectEncrypt.jpg" wide fullword
        $a3 = "ECHO $SMTPServer  = smtp.gmail.com >> %PSScript%" wide fullword
        $a4 = "Injecting Default Template...." wide fullword
        $a5 = "GetVncLoginMethodAsync" ascii fullword
        $a6 = "/c start computerdefaults.exe" wide fullword
    condition:
        all of them
}

