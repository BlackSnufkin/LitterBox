rule Windows_VulnDriver_Biostar_d6cc23af {
    meta:
        author = "Elastic Security"
        id = "d6cc23af-4502-4b18-bd10-17495e6e1443"
        fingerprint = "65a66dc00e62f32fd088809f3c88ceb9d59d264ecff0d9f830c35dfa464baf43"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: BS_HWMIO64_W10.sys, Version: 10.0.1806.2200"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "1d0397c263d51e9fc95bcc8baf98d1a853e1c0401cd0e27c7bf5da3fba1c93a8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 5F 00 48 00 57 00 4D 00 49 00 4F 00 36 00 34 00 5F 00 57 00 31 00 30 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\x98][\x00-\x08]|[\x00-\xff][\x00-\x07])([\x00-\x0e][\x00-\x07]|[\x00-\xff][\x00-\x06])|([\x00-\xff][\x00-\xff])([\x00-\x09][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x0d][\x00-\x07]|[\x00-\xff][\x00-\x06]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_Biostar_68682378 {
    meta:
        author = "Elastic Security"
        id = "68682378-9b49-4bec-b24c-aba8221a62fe"
        fingerprint = "df974c8b5bb60b1b6e95d1c70c968dfca1f1e351f50eed29d215da673d45af19"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: BS_I2cIo.sys, Version: 1.1.0.0"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "55fee54c0d0d873724864dc0b2a10b38b7f40300ee9cae4d9baaf8a202c4049a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 5F 00 49 00 32 00 63 00 49 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x01][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_Biostar_684a5123 {
    meta:
        author = "Elastic Security"
        id = "684a5123-cd84-4133-9530-30bfefd5ad1b"
        fingerprint = "c92b058bbc8a708431bdbe8fc2e793c0a424aa79b25892c83153ffd32e1a89d3"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: BS_RCIO64.sys, Version: 10.0.0.1"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "d205286bffdf09bc033c09e95c519c1c267b40c2ee8bab703c6a2d86741ccd3e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 53 00 5F 00 52 00 43 00 49 00 4F 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x0a][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x09][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

rule Windows_VulnDriver_Biostar_e0b6cf55 {
    meta:
        author = "Elastic Security"
        id = "e0b6cf55-c97d-4799-88a6-30ab0e880b0b"
        fingerprint = "c38c456a008b847c42c45f824b125e7308b8aa41771d3db3d540690b13147abc"
        creation_date = "2022-04-04"
        last_modified = "2022-04-04"
        threat_name = "Windows.VulnDriver.Biostar"
        reference_sample = "73327429c505d8c5fd690a8ec019ed4fd5a726b607cabe71509111c7bfe9fc7e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\BS_RCIO.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

