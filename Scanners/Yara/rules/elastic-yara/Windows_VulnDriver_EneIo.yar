rule Windows_VulnDriver_EneIo_6e01882f {
    meta:
        author = "Elastic Security"
        id = "6e01882f-8394-4e32-8049-fa9c4588b087"
        fingerprint = "8077212bfbadc7f47f2eb76f123a6e4bcda12009293cb975bbeaba77f8c9dcd0"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.EneIo"
        reference_sample = "175eed7a4c6de9c3156c7ae16ae85c554959ec350f1c8aaa6dfe8c7e99de3347"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\Release\\EneIo.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

