rule Windows_Wiper_IsaacWiper_239cd2dc {
    meta:
        author = "Elastic Security"
        id = "239cd2dc-6f93-43fa-98e8-ad7a0edb8a8a"
        fingerprint = "a9c193d7c60b0c793c299b23f672d6428ceb229f2ceb2acbfc1124387954b244"
        creation_date = "2022-03-04"
        last_modified = "2022-04-12"
        threat_name = "Windows.Wiper.IsaacWiper"
        reference_sample = "13037b749aa4b1eda538fda26d6ac41c8f7b1d02d83f47b0d187dd645154e033"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "C:\\ProgramData\\log.txt" wide fullword
        $a2 = "system physical drive -- FAILED" wide fullword
        $a3 = "-- system logical drive: " wide fullword
        $a4 = "start erasing system logical drive " wide fullword
        $a5 = "-- logical drive: " wide fullword
        $a6 = "-- start erasing logical drive " wide fullword
    condition:
        5 of them
}

