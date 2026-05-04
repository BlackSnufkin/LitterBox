rule Windows_VulnDriver_MtcBsv_7f6d642e {
    meta:
        author = "Elastic Security"
        id = "7f6d642e-bf8c-44e7-939f-08513523ee2e"
        fingerprint = "f59ad8d5f19584e76e67689aba1e0d305d451ed6a030c6e2bccd048e0aeb0b0a"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: mtcBSv64.sys, Version: 21.2.0.0"
        threat_name = "Windows.VulnDriver.MtcBsv"
        reference_sample = "ff803017d1acafde6149fe7d463aee23b1c4f6f3b97c698c05f3ca6f07e4df6c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6D 00 74 00 63 00 42 00 53 00 76 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x02][\x00-\x00])([\x00-\x15][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x14][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x01][\x00-\x00])([\x00-\x15][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

