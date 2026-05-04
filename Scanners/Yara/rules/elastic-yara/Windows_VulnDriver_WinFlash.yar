rule Windows_VulnDriver_WinFlash_881758da {
    meta:
        author = "Elastic Security"
        id = "881758da-760c-4c50-81f2-8bd698972ba2"
        fingerprint = "1c64ee1c3fc6bf93e207810a473367c404c824d0eaba15910b00016e23d53637"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.WinFlash"
        reference_sample = "8596ea3952d84eeef8f5dc5b0b83014feb101ec295b2d80910f21508a95aa026"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\WinFlash64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

