rule Windows_VulnDriver_TmComm_333f3851 {
    meta:
        author = "Elastic Security"
        id = "333f3851-5d99-4b22-8af5-1587e9e44ea4"
        fingerprint = "94b718e4450f28b8a9562f89a2fd0e395012051f0af8617d8ab13a45afcd4191"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: TmComm.sys, Version: 8.0.0.0"
        threat_name = "Windows.VulnDriver.TmComm"
        reference_sample = "cc687fe3741bbde1dd142eac0ef59fd1d4457daee43cdde23bb162ef28d04e64"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 6D 00 43 00 6F 00 6D 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x08][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x07][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

