rule Windows_VulnDriver_LLAccess_c57534e8 {
    meta:
        author = "Elastic Security"
        id = "c57534e8-eb38-4714-9262-c489cc6204f1"
        fingerprint = "2eea8941c92353442f7a8986fa3abee06f83824e48bd6a3a5012f7cf76cd543e"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        description = "Name: Corsair LL Access, Version: 1.0.18.0"
        threat_name = "Windows.VulnDriver.LLAccess"
        reference_sample = "000547560fea0dd4b477eb28bf781ea67bf83c748945ce8923f90fdd14eb7a4b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 72 00 73 00 61 00 69 00 72 00 20 00 4C 00 4C 00 20 00 41 00 63 00 63 00 65 00 73 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x12][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x11][\x00-\x00]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

