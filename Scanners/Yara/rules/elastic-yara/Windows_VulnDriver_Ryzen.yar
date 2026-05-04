rule Windows_VulnDriver_Ryzen_7df5a747 {
    meta:
        author = "Elastic Security"
        id = "7df5a747-d924-459d-8363-9c12841ef37f"
        fingerprint = "1bf5d6b2739ce4fe5137cff84e7bfb9389e8d175480094fe831f8f68d84abb16"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: AMDRyzenMasterDriver.sys, Version: 1.5.0.0"
        threat_name = "Windows.VulnDriver.Ryzen"
        reference_sample = "a13054f349b7baa8c8a3fcbd31789807a493cc52224bbff5e412eb2bd52a6433"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 4D 00 44 00 52 00 79 00 7A 00 65 00 6E 00 4D 00 61 00 73 00 74 00 65 00 72 00 44 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x05][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x04][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_Ryzen_9b01c718 {
    meta:
        author = "Elastic Security"
        id = "9b01c718-ba36-4642-b27d-e9310d05d8a5"
        fingerprint = "18ad3df5ae549dddbe1f6f33db534b4fcfc603e0863f8262a8cb9c166a16af67"
        creation_date = "2023-01-22"
        last_modified = "2023-06-13"
        description = "Name: AMDRyzenMasterDriver.sys, Version: <= 1.7.0.0"
        threat_name = "Windows.VulnDriver.Ryzen"
        reference_sample = "bb82d8c29127955d58dff58978605a9daa718425c74c4bce5ae3e53712909148"
        severity = 49
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 4D 00 44 00 52 00 79 00 7A 00 65 00 6E 00 4D 00 61 00 73 00 74 00 65 00 72 00 44 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x07][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x06][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version
}

