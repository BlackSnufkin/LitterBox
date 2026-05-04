rule Windows_Ransomware_Thanos_c3522fd0 : beta {
    meta:
        author = "Elastic Security"
        id = "c3522fd0-90e2-4dd9-82f1-4502689270dd"
        fingerprint = "6d9d6131fd0e3a8585900f4966cb2d1b32e7f5d71b9a65b7a47d80e94bd9f89a"
        creation_date = "2020-11-03"
        last_modified = "2021-08-23"
        description = "Identifies THANOS (Hakbit) ransomware"
        threat_name = "Windows.Ransomware.Thanos"
        reference = "https://labs.sentinelone.com/thanos-ransomware-riplace-bootlocker-and-more-added-to-feature-set/"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $c1 = { 0C 89 45 F0 83 65 EC 00 EB 07 8B 45 EC 40 89 45 EC 83 7D EC 18 }
        $c2 = { E8 C1 E0 04 8B 4D FC C6 44 01 09 00 8B 45 E8 C1 E0 04 8B 4D FC 83 64 01 }
        $c3 = { 00 2F 00 18 46 00 54 00 50 00 20 00 55 00 73 00 65 00 72 00 4E 00 }
    condition:
        2 of ($c*)
}

rule Windows_Ransomware_Thanos_a6c09942 : beta {
    meta:
        author = "Elastic Security"
        id = "a6c09942-0733-40d7-87b7-eb44dd472a35"
        fingerprint = "4abcf47243bebc281566ba4929b20950e3f1bfac8976ae5bc6b8ffda85468ec0"
        creation_date = "2020-11-03"
        last_modified = "2021-08-23"
        description = "Identifies THANOS (Hakbit) ransomware"
        threat_name = "Windows.Ransomware.Thanos"
        reference = "https://labs.sentinelone.com/thanos-ransomware-riplace-bootlocker-and-more-added-to-feature-set/"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $b1 = { 00 57 00 78 00 73 00 49 00 48 00 6C 00 76 00 64 00 58 00 49 00 67 00 5A 00 6D 00 6C 00 73 00 5A 00 58 00 4D 00 67 00 64 00 32 00 56 00 79 00 5A 00 53 00 42 00 6C 00 62 00 6D 00 4E 00 79 00 65 00 58 00 42 00 30 00 5A 00 57 00 51 00 73 00 49 00 47 00 6C 00 6D 00 49 00 48 00 6C 00 76 00 64 00 53 00 42 00 33 00 59 00 57 00 35 00 30 00 49 00 48 00 52 00 76 00 49 00 47 00 64 00 6C 00 64 00 43 00 42 00 30 00 61 00 47 00 56 00 74 00 49 00 47 00 46 00 73 00 62 00 43 00 42 00 69 00 59 00 57 00 4E 00 72 00 4C 00 43 00 42 00 77 00 62 00 47 00 56 00 68 00 63 00 32 00 55 00 67 00 59 00 32 00 46 00 79 00 5A 00 57 00 5A 00 31 00 62 00 47 00 78 00 35 00 49 00 48 00 4A 00 6C 00 59 00 57 00 51 00 67 00 64 00 47 00 68 00 6C 00 49 00 48 00 52 00 6C 00 65 00 48 00 51 00 67 00 62 00 6D 00 39 00 30 00 5A 00 53 00 42 00 73 00 62 00 32 00 4E 00 68 00 64 00 47 00 56 00 6B 00 49 00 47 00 6C 00 75 00 49 00 48 00 6C 00 76 00 64 00 58 00 49 00 67 00 5A 00 47 00 56 00 7A 00 61 00 33 00 52 00 76 00 63 00 43 00 34 00 75 00 4C 00 67 00 3D 00 3D }
        $b2 = { 01 0E 0E 05 00 02 0E 0E 0E 04 00 01 01 0E 04 00 01 0E 0E 06 00 03 01 0E 0E 0E 80 90 55 00 30 00 39 00 47 00 56 00 46 00 64 00 42 00 55 00 6B 00 56 00 63 00 54 00 57 00 6C 00 6A 00 63 00 6D 00 39 00 7A 00 62 00 32 00 5A 00 30 00 58 00 46 00 64 00 70 00 62 00 6D 00 52 00 76 00 64 00 33 00 4D 00 67 00 54 00 6C 00 52 00 63 00 51 00 33 00 56 00 79 00 63 00 6D 00 56 00 75 00 64 00 46 00 5A 00 6C 00 63 00 6E 00 4E 00 70 00 62 00 32 00 35 00 63 00 56 00 32 00 6C 00 }
    condition:
        1 of ($b*)
}

rule Windows_Ransomware_Thanos_e19feca1 : beta {
    meta:
        author = "Elastic Security"
        id = "e19feca1-b131-4045-be0c-d69d55f9a83e"
        fingerprint = "d6654d0b3155d9c64fd4e599ba34d51f110d9dfda6fa1520b686602d9f608f92"
        creation_date = "2020-11-03"
        last_modified = "2021-08-23"
        description = "Identifies THANOS (Hakbit) ransomware"
        threat_name = "Windows.Ransomware.Thanos"
        reference = "https://labs.sentinelone.com/thanos-ransomware-riplace-bootlocker-and-more-added-to-feature-set/"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "<GetIPInfo>b__"
        $a2 = "<Killproc>b__"
        $a3 = "<Crypt>b__"
        $a4 = "<Encrypt2>b__"
        $b1 = "Your files are encrypted."
        $b2 = "I will treat you good if you treat me good too."
        $b3 = "I don't want to loose your files too"
        $b4 = "/c rd /s /q %SYSTEMDRIVE%\\$Recycle.bin" wide fullword
        $b5 = "\\HOW_TO_DECYPHER_FILES.txt" wide fullword
        $b6 = "c3RvcCBTUUxURUxFTUVUUlkkRUNXREIyIC95" wide fullword
        $b7 = "c3RvcCBNQkFNU2VydmljZSAveQ==" wide fullword
        $b8 = "L0MgY2hvaWNlIC9DIFkgL04gL0QgWSAvVCAzICYgRGVsIA==" wide fullword
        $b9 = "c3RvcCBjY0V2dE1nciAveQ==" wide fullword
    condition:
        (4 of ($a*)) or (3 of ($b*))
}

