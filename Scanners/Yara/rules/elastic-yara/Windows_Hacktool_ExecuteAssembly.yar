rule Windows_Hacktool_ExecuteAssembly_f41f4df6 {
    meta:
        author = "Elastic Security"
        id = "f41f4df6-03de-4a03-9dfa-4f9d0f51c2de"
        fingerprint = "4875f516551517ec9423f04a9636b65fc717b9e2c9c40379b027ab126e593d23"
        creation_date = "2023-03-28"
        last_modified = "2023-04-23"
        threat_name = "Windows.Hacktool.ExecuteAssembly"
        reference_sample = "a468ba2ba77aafa2a572c8947d414e74604a7c1c6e68a0b87fbfce4f8854dd61"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $bytes0 = { 33 D8 8B C3 C1 E8 05 03 D8 8B C3 C1 E0 04 33 D8 8B C3 C1 E8 11 03 D8 8B C3 C1 E0 19 33 D8 8B C3 C1 E8 06 03 C3 }
        $bytes1 = { 81 F9 8E 4E 0E EC 74 10 81 F9 AA FC 0D 7C 74 08 81 F9 54 CA AF 91 75 43 }
    condition:
        all of them
}

