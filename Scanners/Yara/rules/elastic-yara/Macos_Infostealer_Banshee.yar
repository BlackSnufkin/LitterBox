rule Macos_Infostealer_Banshee_08f6de7b {
    meta:
        author = "Elastic Security"
        id = "08f6de7b-88d0-4f3b-9c80-8938d2b874a0"
        fingerprint = "4d9726035e318128db04f0ac05e14abc2c452393eb264a9dd83a2aa697fa2dea"
        creation_date = "2024-08-13"
        last_modified = "2025-08-18"
        threat_name = "Macos.Infostealer.Banshee"
        reference_sample = "11aa6eeca2547fcf807129787bec0d576de1a29b56945c5a8fb16ed8bf68f782"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $str_0 = "No debugging, VM, or Russian language detected." ascii fullword
        $str_1 = "Remote IP: " ascii fullword
        $str_2 = "Russian language detected!" ascii fullword
        $str_3 = " is empty or does not exist, skipping." ascii fullword
        $str_4 = "Data posted successfully" ascii fullword
        $binary_0 = { 8B 55 BC 0F BE 08 31 D1 88 08 48 8B 45 D8 48 83 C0 01 48 89 45 D8 E9 }
        $binary_1 = { 48 83 EC 60 48 89 7D C8 48 89 F8 48 89 45 D0 48 89 7D F8 48 89 75 F0 48 89 55 E8 C6 45 E7 00 }
    condition:
        all of ($str_*) or all of ($binary_*)
}

rule Macos_Infostealer_Banshee_5d6bfde9 {
    meta:
        author = "Elastic Security"
        id = "5d6bfde9-f5ac-4988-a8c9-f22954073a79"
        fingerprint = "70f926f87f57018d1cf2b5aac0b8e7975d0ddbe8c1aecbd58a49956e54a27b72"
        creation_date = "2024-09-13"
        last_modified = "2024-10-24"
        threat_name = "Macos.Infostealer.Banshee"
        reference_sample = "03ca50947875b4498013503cd4e26282ff764b8d7a1dc1d801d1d08595986cf8"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $binary_0 = { 89 F0 31 D2 41 F7 F6 0F B6 04 11 41 30 04 37 48 8D 46 01 48 89 C2 4C 09 F2 48 C1 EA 20 }
        $str_0 = { 64 69 74 74 6F 20 2D 63 20 2D 6B 20 25 40 20 25 40 2E 7A 69 70 20 2D 2D 6E 6F 72 73 72 63 20 2D 2D 6E 6F 65 78 74 61 74 74 72 00 }
        $str_1 = "run_controller"
        $str_2 = "initWithEncryptionKey"
        $str_3 = "killall Terminal"
    condition:
        $binary_0 and all of ($str_*)
}

rule Macos_Infostealer_Banshee_cde28dbe {
    meta:
        author = "Elastic Security"
        id = "cde28dbe-10b5-4da4-898c-412d7376e296"
        fingerprint = "ce349c617b19e2fcab1c1d316e16d414a45ed57eb3b3cab91b4c9b177f591875"
        creation_date = "2024-10-29"
        last_modified = "2025-08-18"
        threat_name = "Macos.Infostealer.Banshee"
        reference_sample = "63598afdf56de10043289a7489cccf6c71c203bc68f165f66d2a06e04b65a225"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $str_0 = "dumpKeychainPasswords" ascii fullword
        $str_1 = "compressFolder:" ascii fullword
        $str_2 = "collectWalletData" ascii fullword
        $str_3 = "getMacOSPassword" ascii fullword
        $str_4 = "collectDataFromBrowser:browserPath:" ascii fullword
        $str_5 = "Exodus/exodus.wallet/"
        $b_0 = { 64 69 73 70 6C 61 79 20 64 69 61 6C 6F 67 20 22 54 6F 20 6C 61 75 6E 63 68 20 74 68 65 20 61 70 70 6C 69 63 61 74 69 6F 6E 2C 20 79 6F 75 20 6E 65 65 64 20 74 6F 20 75 70 64 61 74 65 20 74 68 65 20 73 79 73 74 65 6D 20 73 65 74 74 69 6E 67 73 20 0A 0A 50 6C 65 61 73 65 20 65 6E 74 65 72 20 79 6F 75 72 20 70 61 73 73 77 6F 72 64 2E 22 20 77 69 74 68 20 74 69 74 6C 65 20 22 53 79 73 74 65 6D 20 50 72 65 66 65 72 65 6E 63 65 73 22 20 77 69 74 68 20 69 63 6F 6E 20 63 61 75 74 69 6F 6E 20 64 65 66 61 75 6C 74 20 61 6E 73 77 65 72 20 22 22 20 67 69 76 69 6E 67 20 75 70 20 61 66 74 65 72 20 33 30 20 77 69 74 68 20 68 69 64 64 65 6E 20 61 6E 73 77 65 72 27 }
    condition:
        all of ($str_*) or $b_0
}

rule Macos_Infostealer_Banshee_977412ed {
    meta:
        author = "Elastic Security"
        id = "977412ed-4f10-4634-94e9-074629cd2c94"
        fingerprint = "dc49e9e9392ff2b8202df6f011b4494671d8a88c7efbef171b68394709d5706b"
        creation_date = "2025-02-28"
        last_modified = "2025-08-18"
        threat_name = "Macos.Infostealer.Banshee"
        reference_sample = "082579d348d64cece46a726072ed87f4839f44b8a90d415c2383fcdd7566be9f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $binary_0 = { 48 89 C8 48 29 D0 48 D1 E8 48 01 D0 48 C1 E8 02 48 8D 14 C5 00 00 00 00 48 29 D0 48 01 C8 41 8A 04 07 43 88 04 26 }
        $binary_1 = { 48 C7 C2 FF FF FF FF 88 0C 10 41 8A 4C 16 02 48 FF C2 84 C9 75 }
        $binary_2 = { 88 14 31 8A 54 30 02 48 FF C6 84 D2 75 }
        $arm_binary_0 = { 08 7C 40 93 09 7D D6 9B 08 01 09 CB 28 05 48 8B 08 FD 42 D3 08 0D 08 CB 08 C1 20 8B A8 6A 68 38 E8 16 00 38 18 07 00 F1 }
    condition:
        ($binary_0 and $binary_2) or ($binary_1 and $binary_2) or $arm_binary_0
}

rule Macos_Infostealer_Banshee_a49cb4b0 {
    meta:
        author = "Elastic Security"
        id = "a49cb4b0-8c14-439d-9306-db76a421344f"
        fingerprint = "46d147ebb42fd356318d380f82160ecd6ba29efd3f62b846bd945837458d54b5"
        creation_date = "2025-12-30"
        last_modified = "2026-04-06"
        threat_name = "Macos.Infostealer.Banshee"
        reference_sample = "00c68fb8bcb44581f15cb4f888b4dec8cd6d528cacb287dc1bdeeb34299b8c93"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $x64_a = { 49 89 F0 49 D3 E8 44 30 07 48 83 C2 08 48 FF C7 }
        $x64_b = { 88 14 08 8A 54 31 02 48 FF C1 48 83 F9 }
        $arm_a = { 2B 25 CB 9A 4C 01 40 39 8B 01 0B 4A 4B 15 00 38 08 21 00 91 }
        $arm_b = { 0A 69 29 38 8A 05 40 39 29 05 00 91 }
    condition:
        all of ($x64_*) or all of ($arm_*)
}

