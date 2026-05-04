rule Windows_Trojan_SuddenIcon_99487621 {
    meta:
        author = "Elastic Security"
        id = "99487621-88c4-40f6-918a-f1276cc2d2a7"
        fingerprint = "b16f7de530ed27c42bffec4bcfc1232bad34cdaf4e7a9803fce0564e12701ef1"
        creation_date = "2023-03-29"
        last_modified = "2023-03-30"
        threat_name = "Windows.Trojan.SuddenIcon"
        reference = "https://www.elastic.co/security-labs/elastic-users-protected-from-suddenicon-supply-chain-attack"
        reference_sample = "aa4e398b3bd8645016d8090ffc77d15f926a8e69258642191deb4e68688ff973"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "https://raw.githubusercontent.com/IconStorages/images/main/icon%d.ico" wide fullword
        $str2 = "__tutma" ascii fullword
        $str3 = "__tutmc" ascii fullword
        $str4 = "%s: %s" ascii fullword
        $str5 = "%s=%s" ascii fullword
        $seq_obf = { C1 E1 ?? 33 C1 45 8B CA 8B C8 C1 E9 ?? 33 C1 81 C2 ?? ?? ?? ?? 8B C8 C1 E1 ?? 33 C1 41 8B C8 }
        $seq_virtualprotect = { FF 15 ?? ?? ?? ?? 85 C0 74 ?? FF D5 48 85 C0 74 ?? 81 7B ?? CA 7D 0F 00 75 ?? 48 8D 54 24 ?? 48 8D 4C 24 ?? FF D0 8B F8 44 8B 44 24 ?? 4C 8D 4C 24 ?? BA 00 10 00 00 48 8B CD FF 15 ?? ?? ?? ?? }
    condition:
        5 of ($str*) or 2 of ($seq*)
}

rule Windows_Trojan_SuddenIcon_8b07c275 {
    meta:
        author = "Elastic Security"
        id = "8b07c275-f389-4e55-bcec-4b1344cad33d"
        fingerprint = "482f1e668ab63be44a249274e0eaa167e1418c42a8f0e9e85b26e4e23ff57a0d"
        creation_date = "2023-03-29"
        last_modified = "2023-03-30"
        threat_name = "Windows.Trojan.SuddenIcon"
        reference = "https://www.elastic.co/security-labs/elastic-users-protected-from-suddenicon-supply-chain-attack"
        reference_sample = "aa4e398b3bd8645016d8090ffc77d15f926a8e69258642191deb4e68688ff973"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = { 33 C9 E8 ?? ?? ?? ?? 48 8B D8 E8 ?? ?? ?? ?? 44 8B C0 B8 ?? ?? ?? ?? 41 F7 E8 8D 83 ?? ?? ?? ?? C1 FA ?? 8B CA C1 E9 ?? 03 D1 69 CA ?? ?? ?? ?? 48 8D 55 ?? 44 2B C1 48 8D 4C 24 ?? 41 03 C0 }
        $str2 = { B8 ?? ?? ?? ?? 41 BA ?? ?? ?? ?? 0F 11 84 24 ?? ?? ?? ?? 44 8B 06 8B DD BF ?? ?? ?? ?? }
    condition:
        all of them
}

rule Windows_Trojan_SuddenIcon_ac021ae0 {
    meta:
        author = "Elastic Security"
        id = "ac021ae0-67c6-45cf-a467-eb3c2b84b3e4"
        fingerprint = "115d4fc78bae7b5189a94b82ffd6547dfe89cfb66bf59d0e1d77c10fb937d2f7"
        creation_date = "2023-03-30"
        last_modified = "2023-03-30"
        threat_name = "Windows.Trojan.SuddenIcon"
        reference = "https://www.elastic.co/security-labs/elastic-users-protected-from-suddenicon-supply-chain-attack"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "%s\\%s\\%s\\%s" wide fullword
        $str2 = "%s.old" wide fullword
        $str3 = "\n******************************** %s ******************************\n\n" wide fullword
        $str4 = "HostName: %s\\r\\nDomainName: %s\\r\\nOsVersion: %d.%d.%d\\r\\n\\r\\n" wide fullword
        $str5 = "%s\\r\\nDomainName: %s\\r\\nOsVersion: %d.%d.%d\\r\\n\\r\\n" wide fullword
        $str6 = "AppData\\Local\\Google\\Chrome\\User Data" wide fullword
        $str7 = "SELECT url, title FROM urls ORDER BY id DESC LIMIT 500" wide fullword
        $str8 = "SELECT url, title FROM moz_places ORDER BY id DESC LIMIT 500" wide fullword
        $b1 = "\\3CXDesktopApp\\config.json" wide fullword
    condition:
        6 of ($str*) or 1 of ($b*)
}

rule Windows_Trojan_SuddenIcon_bdae76c9 {
    meta:
        author = "Elastic Security"
        id = "bdae76c9-ee1d-4acc-9b1a-4123763ea1b8"
        fingerprint = "8ab0495b59eb84e5506a740a9055c3ec75f25e564761c26f4d829d4ec420a5cf"
        creation_date = "2024-12-16"
        last_modified = "2025-02-11"
        threat_name = "Windows.Trojan.SuddenIcon"
        reference_sample = "11be1803e2e307b647a8a7e02d128335c448ff741bf06bf52b332e0bbf423b03"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $hex_sig = { FE ED FA CE FE ED FA CE }
        $str1 = "D3DCompiler_47.pdb" ascii fullword
    condition:
        all of them
}

