rule Windows_Hacktool_CpuLocker_73b41444 {
    meta:
        author = "Elastic Security"
        id = "73b41444-4c17-4fea-b440-fe7b0a086a7f"
        fingerprint = "3f90517fbeafdccd37e4b8ab0316a91dd18a911cb1f4ffcd4686ab912a0feab4"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.Hacktool.CpuLocker"
        reference_sample = "dbfc90fa2c5dc57899cc75ccb9dc7b102cb4556509cdfecde75b36f602d7da66"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\CPULocker.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

