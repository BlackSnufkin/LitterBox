rule Windows_Trojan_DodgeBox_095012d2 {
    meta:
        author = "Elastic Security"
        id = "095012d2-2804-44f5-b4a1-f9d9c028daf1"
        fingerprint = "0797dbe75dea90df77d35d2d4a259b4402c041bc10f9e52df2ef80b2a5804c9f"
        creation_date = "2024-07-11"
        last_modified = "2024-07-26"
        threat_name = "Windows.Trojan.DodgeBox"
        reference_sample = "c6a3a1ea84251aed908702a1f2a565496d583239c5f467f5dcd0cfc5bfb1a6db"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 53 4F 46 54 57 41 52 45 5C 4D 69 63 72 6F 73 6F 66 74 5C 43 72 79 70 74 6F 67 72 61 70 68 79 00 4D 61 63 68 69 6E 65 47 75 69 64 00 2E 70 64 61 74 61 }
        $a2 = { 5C 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 2E 00 4E 00 45 00 54 00 5C 00 61 00 73 00 73 00 65 00 6D 00 62 00 6C 00 79 00 5C 00 47 00 41 00 43 00 5F 00 4D 00 53 00 49 00 4C 00 5C 00 00 00 00 00 00 00 25 00 6C 00 6C 00 64 00 2E 00 6C 00 6F 00 67 }
        $a3 = { 48 83 EC 20 48 63 51 3C 48 8B D9 33 F6 48 8D 3C 11 8B 8F 90 00 00 00 85 C9 74 21 8B 87 94 00 00 00 85 C0 74 17 44 8B C0 48 03 CB 33 D2 ?? ?? ?? ?? ?? 48 89 B7 90 00 00 00 8B 53 3C 48 63 FA }
        $a4 = { 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 63 51 3C 48 8B D9 33 F6 48 8D 3C 11 8B 8F 90 00 }
        $a5 = { 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 63 59 3C 33 D2 4C 8B C3 48 8B F1 E8 }
    condition:
        any of them
}

