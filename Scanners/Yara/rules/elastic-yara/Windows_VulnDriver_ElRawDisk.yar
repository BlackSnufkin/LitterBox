rule Windows_VulnDriver_ElRawDisk_f9fd1a80 {
    meta:
        author = "Elastic Security"
        id = "f9fd1a80-048f-437f-badb-85d984af202d"
        fingerprint = "3d9dedd033cf07920eaa99b0d1fb654057def2bcef10080b45e1e8a285db8a4e"
        creation_date = "2022-10-07"
        last_modified = "2023-06-13"
        threat_name = "Windows.VulnDriver.ElRawDisk"
        reference_sample = "ed4f2b3db9a79535228af253959a0749b93291ad8b1058c7a41644b73035931b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\elrawdsk.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

