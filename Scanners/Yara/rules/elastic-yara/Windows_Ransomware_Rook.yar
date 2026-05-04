rule Windows_Ransomware_Rook_ee21fa67 {
    meta:
        author = "Elastic Security"
        id = "ee21fa67-bd82-40fb-9c6d-bab5abfe14b3"
        fingerprint = "8ef731590e73f79a13d04db39e58b03d0a29fd8e46a0584b0fcaf57ac0efe473"
        creation_date = "2022-01-14"
        last_modified = "2022-04-12"
        threat_name = "Windows.Ransomware.Rook"
        reference_sample = "c2d46d256b8f9490c9599eea11ecef19fde7d4fdd2dea93604cee3cea8e172ac"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 01 75 09 8B C3 FF C3 48 89 74 C5 F0 48 FF C7 48 83 FF 1A 7C DB }
    condition:
        all of them
}

