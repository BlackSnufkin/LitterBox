rule Windows_Ransomware_Lockbit_89e64044 {
    meta:
        author = "Elastic Security"
        id = "89e64044-74e4-4679-b6ad-bfb9b264330c"
        fingerprint = "ec45013d3ecbc39ffce5ac18d5bf8b0d18bcadd66659975b0a9f26bcae0a5b49"
        creation_date = "2021-08-06"
        last_modified = "2021-10-04"
        threat_name = "Windows.Ransomware.Lockbit"
        reference_sample = "0d6524b9a1d709ecd9f19f75fa78d94096e039b3d4592d13e8dbddf99867182d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "\\LockBit_Ransomware.hta" wide fullword
        $a2 = "\\Registry\\Machine\\Software\\Classes\\Lockbit\\shell" wide fullword
        $a3 = "%s\\%02X%02X%02X%02X.lock" wide fullword
    condition:
        all of them
}

rule Windows_Ransomware_Lockbit_a1c60939 {
    meta:
        author = "Elastic Security"
        id = "a1c60939-e257-420d-87ed-f31f30f2fc2a"
        fingerprint = "a41fb21e82ee893468393428d655b03ce251d23f34acb54bbf01ae0eb86817bf"
        creation_date = "2021-08-06"
        last_modified = "2021-10-04"
        threat_name = "Windows.Ransomware.Lockbit"
        reference_sample = "0d6524b9a1d709ecd9f19f75fa78d94096e039b3d4592d13e8dbddf99867182d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 3C 8B 4C 18 78 8D 04 19 89 45 F8 3B C3 74 70 33 C9 89 4D F4 39 }
    condition:
        all of them
}

rule Windows_Ransomware_Lockbit_369e1e94 {
    meta:
        author = "Elastic Security"
        id = "369e1e94-3fbb-4828-bb78-89d26e008105"
        fingerprint = "9cf4c112c0ee708ae64052926681e8351f1ccefeb558c41e875dbd9e4bdcb5f2"
        creation_date = "2022-07-05"
        last_modified = "2022-07-18"
        threat_name = "Windows.Ransomware.Lockbit"
        reference_sample = "d61af007f6c792b8fb6c677143b7d0e2533394e28c50737588e40da475c040ee"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 66 83 F8 61 72 ?? 66 83 F8 66 77 ?? 66 83 E8 57 EB ?? 66 83 F8 30 72 ?? 66 83 F8 39 77 ?? 66 83 E8 30 EB ?? }
        $a2 = { 8B EC 53 56 57 33 C0 8B 5D ?? 33 C9 33 D2 8B 75 ?? 8B 7D ?? 85 F6 74 ?? 55 8B 6D ?? 8A 54 0D ?? 02 D3 8A 5C 15 ?? 8A 54 1D ?? }
        $a3 = { 53 51 6A ?? 58 0F A2 F7 C1 ?? ?? ?? ?? 0F 95 C0 84 C0 74 ?? 0F C7 F0 0F C7 F2 59 5B C3 6A ?? 58 33 C9 0F A2 F7 C3 ?? ?? ?? ?? 0F 95 C0 84 C0 74 ?? 0F C7 F8 0F C7 FA 59 5B C3 0F 31 8B C8 C1 C9 ?? 0F 31 8B D0 C1 C2 ?? 8B C1 59 5B C3 }
        $b1 = { 6D 00 73 00 65 00 78 00 63 00 68 00 61 00 6E 00 67 00 65 00 00 00 73 00 6F 00 70 00 68 00 6F 00 73 00 }
        $b2 = "LockBit 3.0 the world's fastest and most stable ransomware from 2019" ascii fullword
        $b3 = "http://lockbit"
        $b4 = "Warning! Do not delete or modify encrypted files, it will lead to problems with decryption of files!" ascii fullword
    condition:
        2 of ($a*) or all of ($b*)
}

