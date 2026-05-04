rule Windows_Ransomware_Doppelpaymer_6660d29f : beta {
    meta:
        author = "Elastic Security"
        id = "6660d29f-aca9-4156-90a0-ce64fded281a"
        fingerprint = "8bf4d098b8ce9da99a2ca13fa0759a7185ade1b3ab3b281cd15749d68546d130"
        creation_date = "2020-06-28"
        last_modified = "2021-08-23"
        description = "Identifies DOPPELPAYMER ransomware"
        threat_name = "Windows.Ransomware.Doppelpaymer"
        reference = "https://www.crowdstrike.com/blog/doppelpaymer-ransomware-and-dridex-2/"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Setup run" wide fullword
        $a2 = "RtlComputeCrc32" ascii fullword
    condition:
        2 of ($a*)
}

rule Windows_Ransomware_Doppelpaymer_6ab188da : beta {
    meta:
        author = "Elastic Security"
        id = "6ab188da-4e73-4669-816c-554b2f04ee65"
        fingerprint = "6c33e09e66b337064a1feae5c162f72dc5f6caecaa9829e4ad9fffb10ef3e576"
        creation_date = "2020-06-28"
        last_modified = "2021-08-23"
        description = "Identifies DOPPELPAYMER ransomware"
        threat_name = "Windows.Ransomware.Doppelpaymer"
        reference = "https://www.crowdstrike.com/blog/doppelpaymer-ransomware-and-dridex-2/"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $d1 = { 56 55 55 55 F7 EF B8 56 55 55 55 8B EA F7 E9 8B C2 8B D1 C1 FA 1F 2B C2 C1 FF 1F 2B EF 8D 14 40 B8 F3 1A CA 6B 2B CA 03 E9 F7 ED 8B CD C1 FA 05 C1 F9 1F 2B D1 6B CA B4 03 CD 74 1C 81 E1 03 00 00 80 7D 07 83 E9 01 83 C9 FC 41 8B C1 F7 D8 85 C9 8D 7C 05 04 0F 45 EF 8D 44 55 02 5D 5F C3 }
    condition:
        1 of ($d*)
}

rule Windows_Ransomware_Doppelpaymer_4fb1a155 : beta {
    meta:
        author = "Elastic Security"
        id = "4fb1a155-6448-41e9-829a-e765b7c2570e"
        fingerprint = "f7c1bb3e9d1ad02e7c4edf8accf326330331f92a0f1184bbc19c5bde7505e545"
        creation_date = "2020-06-28"
        last_modified = "2021-08-23"
        description = "Identifies DOPPELPAYMER ransomware"
        threat_name = "Windows.Ransomware.Doppelpaymer"
        reference = "https://www.crowdstrike.com/blog/doppelpaymer-ransomware-and-dridex-2/"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $c1 = { 83 EC 64 8B E9 8B 44 24 ?? 8B 00 0F B7 10 83 FA 5C 75 }
    condition:
        1 of ($c*)
}

