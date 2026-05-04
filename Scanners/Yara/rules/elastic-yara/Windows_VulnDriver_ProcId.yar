rule Windows_VulnDriver_ProcId_86605fa9 {
    meta:
        author = "Elastic Security"
        id = "86605fa9-bf1a-4c2c-87f5-cb656ebe4cf3"
        fingerprint = "6d8d926efd98d6eaa1d06d39fb5babf70abf6f0e639fb74f29f65836a79e4743"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.ProcId"
        reference_sample = "b03f26009de2e8eabfcf6152f49b02a55c5e5d0f73e01d48f5a745f93ce93a29"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\piddrv64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

