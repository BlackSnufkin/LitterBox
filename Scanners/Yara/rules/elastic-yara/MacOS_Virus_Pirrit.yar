rule MacOS_Virus_Pirrit_271b8ed0 {
    meta:
        author = "Elastic Security"
        id = "271b8ed0-937a-4be6-aecb-62535b5aeda7"
        fingerprint = "12b09b2e3a43905db2cfe96d0fd0e735cfc7784ee7b03586c5d437d7c6a1b422"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Virus.Pirrit"
        reference_sample = "7feda05d41b09c06a08c167c7f4dde597ac775c54bf0d74a82aa533644035177"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 35 4A 6A 00 00 32 80 35 44 6A 00 00 75 80 35 3E 6A 00 00 1F 80 35 38 6A 00 00 }
    condition:
        all of them
}

