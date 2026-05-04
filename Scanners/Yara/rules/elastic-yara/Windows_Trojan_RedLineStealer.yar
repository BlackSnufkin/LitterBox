rule Windows_Trojan_RedLineStealer_17ee6a17 {
    meta:
        author = "Elastic Security"
        id = "17ee6a17-161e-454a-baf1-2734995c82cd"
        fingerprint = "a1f75937e83f72f61e027a1045374d3bd17cd387b223a6909b9aed52d2bc2580"
        creation_date = "2021-06-12"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "497bc53c1c75003fe4ae3199b0ff656c085f21dffa71d00d7a3a33abce1a3382"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "RedLine.Logic.SQLite" ascii fullword
        $a2 = "RedLine.Reburn.Data.Browsers.Gecko" ascii fullword
        $a3 = "RedLine.Client.Models.Gecko" ascii fullword
        $b1 = "SELECT * FROM Win32_Process Where SessionId='{0}'" wide fullword
        $b2 = "get_encryptedUsername" ascii fullword
        $b3 = "https://icanhazip.com" wide fullword
        $b4 = "GetPrivate3Key" ascii fullword
        $b5 = "get_GrabTelegram" ascii fullword
        $b6 = "<GrabUserAgent>k__BackingField" ascii fullword
    condition:
        1 of ($a*) or all of ($b*)
}

rule Windows_Trojan_RedLineStealer_f54632eb {
    meta:
        author = "Elastic Security"
        id = "f54632eb-2c66-4aff-802d-ad1c076e5a5e"
        fingerprint = "6a9d45969c4d58181fca50d58647511b68c1e6ee1eeac2a1838292529505a6a0"
        creation_date = "2021-06-12"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "d82ad08ebf2c6fac951aaa6d96bdb481aa4eab3cd725ea6358b39b1045789a25"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "ttp://checkip.amazonaws.com/logins.json" wide fullword
        $a2 = "https://ipinfo.io/ip%appdata%\\" wide fullword
        $a3 = "Software\\Valve\\SteamLogin Data" wide fullword
        $a4 = "get_ScannedWallets" ascii fullword
        $a5 = "get_ScanTelegram" ascii fullword
        $a6 = "get_ScanGeckoBrowsersPaths" ascii fullword
        $a7 = "<Processes>k__BackingField" ascii fullword
        $a8 = "<GetWindowsVersion>g__HKLM_GetString|11_0" ascii fullword
        $a9 = "<ScanFTP>k__BackingField" ascii fullword
        $a10 = "DataManager.Data.Credentials" ascii fullword
    condition:
        6 of ($a*)
}

rule Windows_Trojan_RedLineStealer_3d9371fd {
    meta:
        author = "Elastic Security"
        id = "3d9371fd-c094-40fc-baf8-f0e9e9a54ff9"
        fingerprint = "2d7ff7894b267ba37a2d376b022bae45c4948ef3a70b1af986e7492949b5ae23"
        creation_date = "2022-02-17"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "0ec522dfd9307772bf8b600a8b91fd6facd0bf4090c2b386afd20e955b25206a"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "get_encrypted_key" ascii fullword
        $a2 = "get_PassedPaths" ascii fullword
        $a3 = "ChromeGetLocalName" ascii fullword
        $a4 = "GetBrowsers" ascii fullword
        $a5 = "Software\\Valve\\SteamLogin Data" wide fullword
        $a6 = "%appdata%\\" wide fullword
        $a7 = "ScanPasswords" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_RedLineStealer_63e7e006 {
    meta:
        author = "Elastic Security"
        id = "63e7e006-6c0c-47d8-8090-a6b36f01f3a3"
        fingerprint = "47c7b9a39a5e0a41f26fdf328231eb173a51adfc00948c68332ce72bc442e19e"
        creation_date = "2023-05-01"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "e062c99dc9f3fa780ea9c6249fa4ef96bbe17fd1df38dbe11c664a10a92deece"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 30 68 44 27 25 5B 3D 79 21 54 3A }
        $a2 = { 40 5E 30 33 5D 44 34 4A 5D 48 33 }
        $a3 = { 4B EF 4D FF 44 DD 41 70 44 DC 41 00 44 DC 41 03 43 D9 3E 00 44 }
    condition:
        all of them
}

rule Windows_Trojan_RedLineStealer_f07b3cb4 {
    meta:
        author = "Elastic Security"
        id = "f07b3cb4-a1c5-42c3-a992-d6d9a48bc7a0"
        fingerprint = "8687fa6f540ccebab6000c0c93be4931d874cd04b0692c6934148938bac0026e"
        creation_date = "2023-05-03"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "5e491625475fc25c465fc7f6db98def189c15a133af7d0ac1ecbc8d887c4feb6"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 3C 65 6E 63 72 79 70 74 65 64 5F 6B 65 79 3E 6B 5F 5F 42 61 63 6B 69 6E 67 46 69 65 6C 64 }
        $a2 = { 45 42 37 45 46 31 39 37 33 43 44 43 32 39 35 42 37 42 30 38 46 45 36 44 38 32 42 39 45 43 44 41 44 31 31 30 36 41 46 32 }
    condition:
        all of them
}

rule Windows_Trojan_RedLineStealer_4df4bcb6 {
    meta:
        author = "Elastic Security"
        id = "4df4bcb6-a492-4407-8d8f-bbb835322c98"
        fingerprint = "a9e08bf28e8915615f9b39ab814a46c092b5714ef9133f740a1f1f876bfda2d9"
        creation_date = "2023-05-04"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "9389475bd26c1d3fd04a083557f2797d0ee89dfdd1f7de67775fcd19e61dfbb3"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 34 42 30 35 43 45 42 44 37 44 37 30 46 31 36 30 37 44 34 37 34 43 41 45 31 37 36 46 45 41 45 42 37 34 33 39 37 39 35 46 }
    condition:
        all of them
}

rule Windows_Trojan_RedLineStealer_15ee6903 {
    meta:
        author = "Elastic Security"
        id = "15ee6903-757f-462b-8e1c-1ed8ca667910"
        fingerprint = "d3a380f68477b98b3f5adc11cc597042aa95636cfec0b0a5f2e51c201aa61227"
        creation_date = "2023-05-04"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "46b506cafb2460ca2969f69bcb0ee0af63b6d65e6b2a6249ef7faa21bde1a6bd"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 53 65 65 6E 42 65 66 6F 72 65 33 }
        $a2 = { 73 65 74 5F 53 63 61 6E 47 65 63 6B 6F 42 72 6F 77 73 65 72 73 50 61 74 68 73 }
    condition:
        all of them
}

rule Windows_Trojan_RedLineStealer_6dfafd7b {
    meta:
        author = "Elastic Security"
        id = "6dfafd7b-5188-4ec7-9ba4-58b8f05458e5"
        fingerprint = "b7770492fc26ada1e5cb5581221f59b1426332e57eb5e04922f65c25b92ad860"
        creation_date = "2024-01-05"
        last_modified = "2024-01-12"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "809e303ba26b894f006b8f2d3983ff697aef13b67c36957d98c56aae9afd8852"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 33 38 46 34 33 31 41 35 34 39 34 31 31 41 45 42 33 32 38 31 30 30 36 38 41 34 43 38 33 32 35 30 42 32 44 33 31 45 31 35 }
    condition:
        all of them
}

rule Windows_Trojan_RedLineStealer_983cd7a7 {
    meta:
        author = "Elastic Security"
        id = "983cd7a7-4e7b-413f-b859-b5cbfbf14ae6"
        fingerprint = "6dd74c3b67501506ee43340c07b53ddb94e919d27ad96f55eb4eff3de1470699"
        creation_date = "2024-03-27"
        last_modified = "2024-05-08"
        threat_name = "Windows.Trojan.RedLineStealer"
        reference_sample = "7aa20c57b8815dd63c8ae951e1819c75b5d2deec5aae0597feec878272772f35"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $decrypt_config_bytes = { 72 ?? ?? ?? 70 80 ?? ?? ?? 04 72 ?? ?? ?? 70 80 ?? ?? ?? 04 72 ?? ?? ?? 70 80 ?? ?? ?? 04 72 ?? ?? ?? 70 80 ?? ?? ?? 04 [0-6] 2A }
        $str1 = "net.tcp://" wide
        $str2 = "\\Discord\\Local Storage\\leveldb" wide
    condition:
        all of them
}

