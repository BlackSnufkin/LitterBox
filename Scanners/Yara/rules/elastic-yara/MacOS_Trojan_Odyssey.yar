rule MacOS_Trojan_Odyssey_10876e25 {
    meta:
        author = "Elastic Security"
        id = "10876e25-d9ab-4da9-ba23-df5c24761406"
        fingerprint = "d06cd067ce7a1366f1d55dbdc483a46f1809039fa663c1f3dee89ec6bb09e3dc"
        creation_date = "2026-03-02"
        last_modified = "2026-04-06"
        threat_name = "MacOS.Trojan.Odyssey"
        reference_sample = "61b0b147bf9bec52818af09d10ca7b81bb94c07d964684f10360abfe426014ba"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $x86_1 = { 69 C0 8F BC 00 00 48 89 C2 49 0F AF D6 48 C1 EA 2F 69 D2 11 93 00 00 29 D0 48 FF C1 48 }
        $x86_2 = { 69 C0 8F BC 00 00 48 89 C7 48 0F AF FE 48 C1 EF 2F 69 FF 11 93 00 00 29 F8 48 FF C1 48 }
        $arm_1 = { EC 91 97 52 6D A0 90 52 6D F6 A6 72 4E 62 92 52 }
        $arm_2 = { 4F 69 68 38 EF 01 09 4A 6F 69 28 38 29 7D 0C 1B 2F 7D AD 9B EF FD 6D D3 E9 A5 0E 1B 08 05 00 91 1F }
    condition:
        2 of ($x86_*) or 2 of ($arm_*)
}

