rule Multi_Trojan_FinalDraft_81975d51 {
    meta:
        author = "Elastic Security"
        id = "81975d51-96e9-4a49-97ee-56e2c60e9702"
        fingerprint = "a2d5e2f472499ad6c5ff052eded73fa182bb20cecb9c3921f37bd779a2a77c9b"
        creation_date = "2024-12-03"
        last_modified = "2025-02-04"
        threat_name = "Multi.Trojan.FinalDraft"
        reference_sample = "fa2a6dbc83fe55df848dfcaaf3163f8aaefe0c9727b3ead1da6b9fa78b598f2b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "[-] socket() failed!"
        $a2 = "MailFolders/drafts/messages?$filter=Subject"
        $a3 = "{\"subject\":\"p_%llu\",\"body\":"
        $a4 = "COutLookTransChannel"
        $a5 = "CTransChannel"
        $a6 = "Chrome/40.0.2214.85 Safari/537.36"
    condition:
        3 of them
}

rule Multi_Trojan_FinalDraft_69deb8cd {
    meta:
        author = "Elastic Security"
        id = "69deb8cd-050b-4b92-86c2-ea54f836ce72"
        fingerprint = "3e48740092918896132e801ae4d850ef804f9dd6c8db96b80065224566c17819"
        creation_date = "2024-12-03"
        last_modified = "2025-02-04"
        threat_name = "Multi.Trojan.FinalDraft"
        reference_sample = "fa2a6dbc83fe55df848dfcaaf3163f8aaefe0c9727b3ead1da6b9fa78b598f2b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = { 33 FF C7 44 24 20 3A 00 77 00 4C 8B F1 C7 44 24 24 74 00 66 00 48 83 C8 FF C7 44 24 28 62 00 62 00 C7 44 24 2C 71 00 00 00 48 8D 4C 24 20 }
        $a2 = { 48 81 EC B0 00 00 00 48 8B 05 00 5B 05 00 48 33 C4 48 89 84 24 A0 00 00 00 0F 57 C0 0F 11 44 24 48 4C 8B C2 48 8D 54 24 48 E8 00 0B 00 00 90 48 83 7C 24 50 00 0F 84 31 01 00 00 48 8B 7C 24 48 }
        $a3 = { 48 8D 7C 24 48 C6 43 40 00 48 C7 43 48 00 00 00 00 48 C7 43 50 00 00 00 00 48 89 43 68 48 8B ?? ?? ?? ?? 00 48 C7 43 58 00 00 00 00 C7 43 60 00 00 00 00 48 C7 43 70 00 00 00 00 C6 43 78 00 48 8D B0 FD 00 00 00 }
        $a4 = { 48 83 EC 58 B9 0D 00 00 00 BE 1E 00 00 00 64 48 8B 04 25 28 00 00 00 48 89 44 24 48 31 C0 48 8D 7C 24 14 48 C7 44 24 08 00 00 00 00 F3 AB 48 8D 7C 24 14 E8 }
    condition:
        any of them
}

