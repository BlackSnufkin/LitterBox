rule Windows_VulnDriver_TopazOFD_86b87a80 {
    meta:
        author = "Elastic Security"
        id = "86b87a80-1080-4a24-8cdf-352ded07e95d"
        fingerprint = "232be04d29f158eef348266f55c94544de4f37541a55aa200aef1025b0b1a5ea"
        creation_date = "2026-01-22"
        last_modified = "2026-02-02"
        description = "Subject: TPZ SOLUCOES DIGITAIS LTDA, Name: wsftprm.sys, Version: 2.0.0.0, Product Name: wsddprm"
        threat_name = "Windows.VulnDriver.TopazOFD"
        reference_sample = "ff5dbdcf6d7ae5d97b6f3ef412df0b977ba4a844c45b30ca78c0eeb2653d69a8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 50 5A 20 53 4F 4C 55 43 4F 45 53 20 44 49 47 49 54 41 49 53 20 4C 54 44 41 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 [1-8] 77 00 73 00 66 00 74 00 70 00 72 00 6D 00 2E 00 73 00 79 00 73 00 00 }
        $product_version = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E [1-8] 32 00 2E 00 30 00 2E 00 30 00 2E 00 30 }
        $product_name = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 [1-8] 77 00 73 00 64 00 64 00 70 00 72 00 6D 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $product_version and $product_name
}

