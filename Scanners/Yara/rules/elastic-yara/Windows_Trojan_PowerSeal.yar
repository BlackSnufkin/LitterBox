rule Windows_Trojan_PowerSeal_d63f5e54 {
    meta:
        author = "Elastic Security"
        id = "d63f5e54-6be1-453d-a96e-083a025deba2"
        fingerprint = "bc63511a0b12edaf7a2ace02f79ab9a2dbea5a0879fd976cc91308f98bac1c52"
        creation_date = "2023-03-16"
        last_modified = "2023-05-26"
        threat_name = "Windows.Trojan.PowerSeal"
        reference = "https://www.elastic.co/security-labs/elastic-charms-spectralviper"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "PowerSeal.dll" wide fullword
        $a2 = "InvokePs" ascii fullword
        $a3 = "amsiInitFailed" wide fullword
        $a4 = "is64BitOperatingSystem" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_PowerSeal_2e50f393 {
    meta:
        author = "Elastic Security"
        id = "2e50f393-40c0-49f7-882e-33f914eff32d"
        fingerprint = "9b7beb5af64bc57d78cfb8f5bf8134461d8f2fbe7c935a0fa2b44fb51160a28d"
        creation_date = "2023-05-10"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.PowerSeal"
        reference = "https://www.elastic.co/security-labs/elastic-charms-spectralviper"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "[+] Loading PowerSeal"
        $a2 = "[!] Failed to exec PowerSeal"
        $a3 = "AppDomain: unable to get the name!"
    condition:
        2 of them
}

