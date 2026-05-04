rule Windows_VulnDriver_Iqvw_b8b45e6b {
    meta:
        author = "Elastic Security"
        id = "b8b45e6b-9729-4e0e-ad08-488e1a4306e0"
        fingerprint = "eeabf1c506ac6db4de3279a8b03d676f95c6d93dad6ae0173f2adec2dae41b95"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: iQVW64.SYS, Version: 1.4.0.0"
        threat_name = "Windows.VulnDriver.Iqvw"
        reference_sample = "37c637a74bf20d7630281581a8fae124200920df11ad7cd68c14c26cc12c5ec9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 69 00 51 00 56 00 57 00 36 00 34 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x04][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x03][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

