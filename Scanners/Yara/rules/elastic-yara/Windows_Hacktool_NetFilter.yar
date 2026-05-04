rule Windows_Hacktool_NetFilter_e8243dae {
    meta:
        author = "Elastic Security"
        id = "e8243dae-33d9-4b54-8f4a-ba5cf5241767"
        fingerprint = "1542c32471f5d3f20beeb60c696085548d675f5d1cab1a0ef85a7060b01f0349"
        creation_date = "2022-04-04"
        last_modified = "2023-06-13"
        threat_name = "Windows.Hacktool.NetFilter"
        reference_sample = "760be95d4c04b10df89a78414facf91c0961020e80561eee6e2cb94b43b76510"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "[NetFlt]:CTRL NDIS ModifyARP"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_Hacktool_NetFilter_dd576d28 {
    meta:
        author = "Elastic Security"
        id = "dd576d28-b3e7-46b7-b19f-af37af434082"
        fingerprint = "b47477c371819a456ab24e158d6649e89b4d1756dc6da0b783b351d40b034fac"
        creation_date = "2022-04-04"
        last_modified = "2023-06-13"
        threat_name = "Windows.Hacktool.NetFilter"
        reference_sample = "88cfe6d7c81d0064045c4198d6ec7d3c50dc3ec8e36e053456ed1b50fc8c23bf"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\NetProxyDriver.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_Hacktool_NetFilter_b4f2a520 {
    meta:
        author = "Elastic Security"
        id = "b4f2a520-88bf-447e-bbc4-5d8bfd2c9753"
        fingerprint = "1d8da6f78149e2db6b54faa381ce8eb285930226a5b4474e04937893c831809f"
        creation_date = "2022-04-04"
        last_modified = "2023-06-13"
        threat_name = "Windows.Hacktool.NetFilter"
        reference_sample = "5d0d5373c5e52c4405f4bd963413e6ef3490b7c4c919ec2d4e3fb92e91f397a0"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\netfilterdrv.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_Hacktool_NetFilter_1cae6e26 {
    meta:
        author = "Elastic Security"
        id = "1cae6e26-b0ce-4f53-b88d-975b52ebcca7"
        fingerprint = "27003a6c9ad814e1ab2e7e284acfebdd18c9dd2af66eb9f44e5a9d59445fa086"
        creation_date = "2022-04-04"
        last_modified = "2023-06-13"
        threat_name = "Windows.Hacktool.NetFilter"
        reference_sample = "e2ec3b2a93c473d88bfdf2deb1969d15ab61737acc1ee8e08234bc5513ee87ea"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "\\Driver_Map.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

