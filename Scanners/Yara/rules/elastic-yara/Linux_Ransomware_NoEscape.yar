rule Linux_Ransomware_NoEscape_6de58e0c {
    meta:
        author = "Elastic Security"
        id = "6de58e0c-67f9-4344-9fe9-26bfc37e537e"
        fingerprint = "60a160abcbb6d93d9ee167663e419047f3297d549c534cbe66d035a0aa36d806"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.NoEscape"
        reference_sample = "46f1a4c77896f38a387f785b2af535f8c29d40a105b63a259d295cb14d36a561"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "HOW_TO_RECOVER_FILES.txt"
        $a2 = "large_file_size_mb"
        $a3 = "note_text"
    condition:
        all of them
}

