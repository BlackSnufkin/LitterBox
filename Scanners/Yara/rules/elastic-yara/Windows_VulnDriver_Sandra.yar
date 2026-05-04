rule Windows_VulnDriver_Sandra_5d112feb {
    meta:
        author = "Elastic Security"
        id = "5d112feb-dc0a-464c-9753-695bb510f5a8"
        fingerprint = "13572e1155a5417549508952504b891f0e4f40cb6ff911bdda6f152c051c401c"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: SANDRA, Version: 10.12.0.0"
        threat_name = "Windows.VulnDriver.Sandra"
        reference_sample = "3a364a7a3f6c0f2f925a060e84fb18b16c118125165b5ea6c94363221dc1b6de"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 41 00 4E 00 44 00 52 00 41 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x0c][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x09][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x0b][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_Sandra_612a7a16 {
    meta:
        author = "Elastic Security"
        id = "612a7a16-b616-4a70-9994-cb5aebfa0ca9"
        fingerprint = "ead3bd8256fbb5d26c4a177298a5cdd14e5eeb73d9336999c0a68ece9efa2d55"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: sandra.sys, Version: 10.12.0.0"
        threat_name = "Windows.VulnDriver.Sandra"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 61 00 6E 00 64 00 72 00 61 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x0c][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x09][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x0b][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

