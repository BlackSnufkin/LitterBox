rule Linux_Worm_Generic_920d273f {
    meta:
        author = "Elastic Security"
        id = "920d273f-5b2b-4eec-a2b3-8d411f2ea181"
        fingerprint = "3d4dd13b715249710bc2a02b1628fb68bcccebab876ff6674cad713e93ac53d2"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Worm.Generic"
        reference_sample = "04a65bc73fab91f654d448b2d7f8f15ac782965dcdeec586e20b5c7a8cc42d73"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E9 E5 49 86 49 A4 1A 70 C7 A4 AD 2E E9 D9 09 F5 AD CB ED FC 3B }
    condition:
        all of them
}

rule Linux_Worm_Generic_98efcd38 {
    meta:
        author = "Elastic Security"
        id = "98efcd38-d579-46f7-a8f8-360f799a5078"
        fingerprint = "d6cec73bb6093dbc6d26566c174d0d0f6448f431429edef0528c9ec1c83177fa"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Worm.Generic"
        reference_sample = "87507f5cd73fffdb264d76db9b75f30fe21cc113bcf82c524c5386b5a380d4bb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 14 75 E1 8B 5A 24 01 EB 66 8B 0C 4B 8B 5A 1C 01 EB 8B 04 8B }
    condition:
        all of them
}

rule Linux_Worm_Generic_bd64472e {
    meta:
        author = "Elastic Security"
        id = "bd64472e-92a2-4d64-8008-b82d7ca33b1d"
        fingerprint = "1978baa7ff5457e06433fd45db098aefd39ea53d3f29e541eef54890a25a9dce"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Worm.Generic"
        reference_sample = "b3334a3b61b1a3fc14763dc3d590100ed5e85a97493c89b499b02b76f7a0a7d0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 C0 89 45 EC 83 7D EC FF 75 38 68 54 90 04 08 }
    condition:
        all of them
}

rule Linux_Worm_Generic_3ff8f75b {
    meta:
        author = "Elastic Security"
        id = "3ff8f75b-619e-4090-8ea4-aedc8bdf61a4"
        fingerprint = "011f0cd72ebb428775305c84eac69c5ff4800de6e1d8b4d2110d5445b1aae10f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Worm.Generic"
        reference_sample = "991175a96b719982f3a846df4a66161a02225c21b12a879e233e19124e90bd35"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 3A DF FE 00 66 0F 73 FB 04 66 0F 6F D3 66 0F EF D9 66 0F 6F EE 66 0F 70 }
    condition:
        all of them
}

