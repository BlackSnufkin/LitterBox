rule Windows_VulnDriver_TrueSight_7429ac81 {
    meta:
        author = "Elastic Security"
        id = "7429ac81-04d5-4946-9fff-abe7be98fc4d"
        fingerprint = "775137e1f402f347504377eb86aa95a522e50237fa3b09db4f11def2af24b609"
        creation_date = "2024-06-21"
        last_modified = "2024-09-09"
        threat_name = "Windows.VulnDriver.TrueSight"
        reference_sample = "bfc2ef3b404294fe2fa05a8b71c7f786b58519175b7202a69fe30f45e607ff1c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 54 00 72 00 75 00 65 00 73 00 69 00 67 00 68 00 74 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x03][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x02][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x02][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version
}

