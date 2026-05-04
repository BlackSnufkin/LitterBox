rule Windows_VulnDriver_Segwin_04a3962e {
    meta:
        author = "Elastic Security"
        id = "04a3962e-4622-4d83-b0e7-4d77c8a81ab6"
        fingerprint = "e3c5441e4c26f7c5ba5db8a4b7618d870a5dd7b70d9373d80d81497bc0f73739"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: segwindrvx64.sys, Version: 100.0.7.2"
        threat_name = "Windows.VulnDriver.Segwin"
        reference_sample = "65329dad28e92f4bcc64de15c552b6ef424494028b18875b7dba840053bc0cdd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 65 00 67 00 77 00 69 00 6E 00 64 00 72 00 76 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x64][\x00-\x00])([\x00-\x02][\x00-\x00])([\x00-\x07][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x63][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x64][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x06][\x00-\x00]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

