rule Windows_Hacktool_ProcessHacker_3d01069e {
    meta:
        author = "Elastic Security"
        id = "3d01069e-7afb-4da0-b7ac-23f90db26495"
        fingerprint = "5d6a0835ac6c0548292ff11741428d7b2f4421ead6d9e2ca35379cbceb6ee68c"
        creation_date = "2022-03-30"
        last_modified = "2022-03-30"
        threat_name = "Windows.Hacktool.ProcessHacker"
        reference_sample = "70211a3f90376bbc61f49c22a63075d1d4ddd53f0aefa976216c46e6ba39a9f4"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = "OriginalFilename\x00kprocesshacker.sys" wide fullword
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name
}

