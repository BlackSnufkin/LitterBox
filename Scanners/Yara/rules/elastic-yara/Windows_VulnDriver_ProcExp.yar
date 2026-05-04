rule Windows_VulnDriver_ProcExp_aeb4e5c0 {
    meta:
        author = "Elastic Security"
        id = "aeb4e5c0-5ed5-4ecf-95a5-a741c105f02f"
        fingerprint = "b06d9e07aebfe4acadb717f7a8534feb6863b0649cd10fbbf9b53587a855ea01"
        creation_date = "2022-04-04"
        last_modified = "2022-10-26"
        description = "Name: procexp.Sys, Version: 16.65535.65535.65535"
        threat_name = "Windows.VulnDriver.ProcExp"
        reference_sample = "440883cd9d6a76db5e53517d0ec7fe13d5a50d2f6a7f91ecfc863bc3490e4f5c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 72 00 6F 00 63 00 65 00 78 00 70 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\xff][\x00-\xff])([\x00-\x10][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\xff][\x00-\xff])([\x00-\x0f][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\xfe][\x00-\xff])([\x00-\x10][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\xff][\x00-\xff])([\x00-\x10][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xfe][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

