rule Windows_VulnDriver_WinDivert_25991186 {
    meta:
        author = "Elastic Security"
        id = "25991186-7a44-446c-9e97-e91bb9adfd77"
        fingerprint = "43c7f0dfe43c64d644fcb0171433a8af0f7b4c38f7601d42923762c3d882ac31"
        creation_date = "2024-06-20"
        last_modified = "2024-07-02"
        threat_name = "Windows.VulnDriver.WinDivert"
        reference_sample = "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 57 00 69 00 6E 00 44 00 69 00 76 00 65 00 72 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name
}

