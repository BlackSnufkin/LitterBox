rule Windows_Trojan_Hawkeye_77c36ace {
    meta:
        author = "Elastic Security"
        id = "77c36ace-3857-43f8-a6de-596ba7964b6f"
        fingerprint = "c9a1c61b4fa78c46d493e1b307e9950bd714ba4e5a6249f15a3b86a74b7638e5"
        creation_date = "2021-08-16"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Hawkeye"
        reference_sample = "28e28025060f1bafd4eb96c7477cab73497ca2144b52e664b254c616607d94cd"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Logger - Key Recorder - [" wide fullword
        $a2 = "http://whatismyipaddress.com/" wide fullword
        $a3 = "Keylogger Enabled: " wide fullword
        $a4 = "LoadPasswordsSeaMonkey" wide fullword
        $a5 = "\\.minecraft\\lastlogin" wide fullword
    condition:
        all of them
}

rule Windows_Trojan_Hawkeye_975d546c {
    meta:
        author = "Elastic Security"
        id = "975d546c-286b-4753-b894-d6ed0aa832f3"
        fingerprint = "5bbdb07fa6dd3e415f49d7f4fbc249c078ae42ebd81cad3015e32dfdc8f7cda6"
        creation_date = "2023-03-23"
        last_modified = "2023-04-23"
        threat_name = "Windows.Trojan.Hawkeye"
        reference_sample = "aca133bf1d72cf379101e6877871979d6e6e8bc4cc692a5ba815289735014340"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s1 = "api.telegram.org"
        $s2 = "Browsers/Passwords"
        $s3 = "Installed Browsers.txt"
        $s4 = "Browsers/AutoFills"
        $s5 = "Passwords.txt"
        $s6 = "System Information.txt"
    condition:
        all of them
}

