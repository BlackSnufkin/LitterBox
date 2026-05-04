rule MacOS_Infostealer_MdQueryTCC_142313cb {
    meta:
        author = "Elastic Security"
        id = "142313cb-4726-442d-957c-5078440b8940"
        fingerprint = "280fa2c49461d0b53425768b9114696104c3ed0241ed157c22e36cdbaa334ac9"
        creation_date = "2023-04-11"
        last_modified = "2024-08-19"
        threat_name = "MacOS.Infostealer.MdQueryTCC"
        reference_sample = "d895075057e491b34b0f8c0392b44e43ade425d19eaaacea6ef8c5c9bd3487d8"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $string1 = { 6B 4D 44 49 74 65 6D 44 69 73 70 6C 61 79 4E 61 6D 65 20 ( 3D | 3D ) 20 2A 54 43 43 2E 64 62 }
    condition:
        any of them
}

