rule Windows_Rootkit_AbyssWorker_4ef8536c {
    meta:
        author = "Elastic Security"
        id = "4ef8536c-9819-474c-b7e2-269c525249e5"
        fingerprint = "1885261cb257b498b187935383087d172ad732477d35836d99a20683b1c7f669"
        creation_date = "2025-02-05"
        last_modified = "2025-02-11"
        threat_name = "Windows.Rootkit.AbyssWorker"
        reference_sample = "6a2a0f9c56ee9bf7b62e1d4e1929d13046cd78a93d8c607fe4728cc5b1e8d050"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "7N6bCAoECbItsUR5-h4Rp2nkQxybfKb0F-wgbJGHGh20pWUuN1-ZxfXdiOYps6HTp0X" wide fullword
        $a2 = "\\??\\fqg0Et4KlNt4s1JT" wide fullword
        $a3 = "\\device\\czx9umpTReqbOOKF" wide fullword
        $a4 = { 48 35 04 82 66 00 48 8B 4C 24 28 48 81 F1 17 24 53 00 48 03 C1 48 89 04 24 48 8B 04 24 48 C1 E0 05 48 8B 0C 24 48 C1 E9 1B 48 0B C1 }
        $a5 = { 48 35 04 82 66 00 48 8B 4C 24 08 48 0F AF C8 48 8B C1 48 8B 4C 24 08 48 81 E1 17 24 53 00 48 03 C1 }
    condition:
        2 of ($a*)
}

