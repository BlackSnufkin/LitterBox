rule Windows_VulnDriver_Rtkio_13b3c88b {
    meta:
        author = "Elastic Security"
        id = "13b3c88b-daa7-4402-ad31-6fc7d4064087"
        fingerprint = "3788e6a7a759796a2675116e4d291324f97114773cf53345f15796566266f702"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: rtkio.sys"
        threat_name = "Windows.VulnDriver.Rtkio"
        reference_sample = "478917514be37b32d5ccf76e4009f6f952f39f5553953544f1b0688befd95e82"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name
}

rule Windows_VulnDriver_Rtkio_d595781e {
    meta:
        author = "Elastic Security"
        id = "d595781e-67c1-47bf-a7ea-bb4a9ba33879"
        fingerprint = "efe0871703d5c146764c4a7ac9c80ae4e635dc6dd0e718e6ddc4c39b18ca9fdd"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: rtkio64.sys"
        threat_name = "Windows.VulnDriver.Rtkio"
        reference_sample = "4ed2d2c1b00e87b926fb58b4ea43d2db35e5912975f4400aa7bd9f8c239d08b7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 36 00 34 00 2E 00 73 00 79 00 73 00 20 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name
}

rule Windows_VulnDriver_Rtkio_b09af431 {
    meta:
        author = "Elastic Security"
        id = "b09af431-307b-40e2-bac5-5865c1ad54c8"
        fingerprint = "e62a497acc1ee04510aa42ca96c5265e16b3be665f99e7dfc09ecc38055aca5b"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: rtkiow8x64.sys"
        threat_name = "Windows.VulnDriver.Rtkio"
        reference_sample = "b205835b818d8a50903cf76936fcf8160060762725bd74a523320cfbd091c038"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 77 00 38 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name
}

rule Windows_VulnDriver_Rtkio_5693e967 {
    meta:
        author = "Elastic Security"
        id = "5693e967-dbe4-457c-8b0c-404774871ac0"
        fingerprint = "4de76b2d42b523c4bfefeee8905e8f431168cb59e18049563f9942e97c276e46"
        creation_date = "2022-04-07"
        last_modified = "2022-04-07"
        description = "Name: rtkiow10x64.sys"
        threat_name = "Windows.VulnDriver.Rtkio"
        reference_sample = "ab8f2217e59319b88080e052782e559a706fa4fb7b8b708f709ff3617124da89"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 77 00 31 00 30 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 20 00 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name
}

