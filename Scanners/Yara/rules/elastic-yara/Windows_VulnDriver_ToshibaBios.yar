rule Windows_VulnDriver_ToshibaBios_2891972a {
    meta:
        author = "Elastic Security"
        id = "2891972a-901d-47d3-ae73-39b7c601dd19"
        fingerprint = "154a771873bef03d1cc63cb2e270a62d42bbd2aa9027a59bc027b3ff88641192"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: NCHGBIOS2x64.SYS, Version: 4.2.4.0"
        threat_name = "Windows.VulnDriver.ToshibaBios"
        reference_sample = "314384b40626800b1cde6fbc51ebc7d13e91398be2688c2a58354aa08d00b073"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 43 00 48 00 47 00 42 00 49 00 4F 00 53 00 32 00 78 00 36 00 34 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x02][\x00-\x00])([\x00-\x04][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x04][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x01][\x00-\x00])([\x00-\x04][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x02][\x00-\x00])([\x00-\x04][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x03][\x00-\x00]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

