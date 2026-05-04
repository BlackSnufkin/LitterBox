rule Windows_VulnDriver_WinIo_c9cc6d00 {
    meta:
        author = "Elastic Security"
        id = "c9cc6d00-b1ed-4bab-b0f7-4f0d6c03bf08"
        fingerprint = "d9050466a2894b63ae86ec8888046efb49053edcc20287b9f17a4e6340a9cf92"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.WinIo"
        reference_sample = "e1980c6592e6d2d92c1a65acad8f1071b6a404097bb6fcce494f3c8ac31385cf"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\WinioSys.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_VulnDriver_WinIo_b0f21a70 {
    meta:
        author = "Elastic Security"
        id = "b0f21a70-b563-4b18-8ef9-73885125e88b"
        fingerprint = "00d8142a30e9815f8e4c53443221fc1c3882c8b6f68e77a8ed7ffe4fc8852488"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.WinIo"
        reference_sample = "9fc29480407e5179aa8ea41682409b4ea33f1a42026277613d6484e5419de374"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "IOCTL_WINIO_WRITEMSR"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

