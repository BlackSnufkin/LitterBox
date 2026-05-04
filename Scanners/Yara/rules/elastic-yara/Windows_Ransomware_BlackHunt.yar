rule Windows_Ransomware_BlackHunt_7b46cb9c {
    meta:
        author = "Elastic Security"
        id = "7b46cb9c-4601-4be0-a2de-6a4f27d1a446"
        fingerprint = "1e46e2de840bfd557147e686eb00c350d00f6d1c6b2b8d1df98165c73cbe89ba"
        creation_date = "2024-03-12"
        last_modified = "2024-03-21"
        threat_name = "Windows.Ransomware.BlackHunt"
        reference_sample = "6c4e968c9b53906ba0e86a41eccdabe2b736238cb126852023e15850e956293d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "#BlackHunt_ReadMe.txt" wide fullword
        $a2 = "#BlackHunt_Private.key" wide fullword
        $a3 = "#BlackHunt_ID.txt" wide fullword
        $a4 = "BLACK_HUNT_MUTEX" ascii fullword
        $a5 = "BlackKeys" ascii fullword
        $a6 = "ENCRYPTED VOLUME : %dGB" ascii fullword
        $a7 = "RUNNING TIME : %02dm:%02ds" ascii fullword
    condition:
        4 of them
}

