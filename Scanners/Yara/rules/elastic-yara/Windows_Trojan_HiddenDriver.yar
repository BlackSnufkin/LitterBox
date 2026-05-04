rule Windows_Trojan_HiddenDriver_e26590fd {
    meta:
        author = "Elastic Security"
        id = "e26590fd-a560-4312-ba2f-4131f5817410"
        fingerprint = "fe876e1cc0663fd41742a93807a4d49972fb92c3abf6560e323d1e31f8a9eb69"
        creation_date = "2025-10-02"
        last_modified = "2025-10-13"
        threat_name = "Windows.Trojan.HiddenDriver"
        reference_sample = "f9dd0b57a5c133ca0c4cab3cca1ac8debdc4a798b452167a1e5af78653af00c1"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $activeProcessLinksOffsets = { C7 44 24 20 E8 00 00 00 C7 44 24 24 88 01 00 00 C7 44 24 28 E8 02 00 00 C7 44 24 2C F0 02 00 00 C7 44 24 30 48 04 00 00 }
        $alloc_table = { 48 83 63 78 00 48 8D 8B 88 00 00 00 83 A3 80 00 00 00 00 B8 01 00 00 00 8B D0 48 89 43 68 45 33 C0 89 43 70 }
        $str_0 = "InitializePsMonitor"
        $str_1 = "image load notify registartion failed with code:%08x"
        $str_2 = "file-system mini-filter haven't started"
        $str_3 = "can't activate stealth mode"
    condition:
        $activeProcessLinksOffsets or $alloc_table or (all of ($str_*))
}

