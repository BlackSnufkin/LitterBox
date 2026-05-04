rule Windows_Shellcode_Rdi_edc62a10 {
    meta:
        author = "Elastic Security"
        id = "edc62a10-7cb1-4fda-a15c-86d40d510ffd"
        fingerprint = "1cee85457eb31be126a41d4e332735957cf4a928fdf4b5253380b6c97605d069"
        creation_date = "2023-06-23"
        last_modified = "2023-07-10"
        threat_name = "Windows.Shellcode.Rdi"
        reference_sample = "64485ffc283e981c8b77db5a675c7ba2a04d3effaced522531185aa46eb6a36b"
        severity = 90
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { E8 00 00 00 00 59 49 89 C8 48 81 C1 23 0B 00 00 BA [10] 00 41 B9 04 00 00 00 56 48 89 E6 48 83 E4 F0 48 83 EC 30 C7 }
    condition:
        all of them
}

rule Windows_Shellcode_Rdi_eee75d2c {
    meta:
        author = "Elastic Security"
        id = "eee75d2c-78ef-460f-be96-4638443952fb"
        fingerprint = "2b8f840cecec00ce3112ea58e4e957e1b0754380e14a8fc8a39abc36feb077e9"
        creation_date = "2023-08-25"
        last_modified = "2023-11-02"
        threat_name = "Windows.Shellcode.Rdi"
        reference_sample = "8c4de69e89dcc659d2fff52d695764f1efd7e64e0a80983ce6d0cb9eeddb806c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 81 EC 14 01 00 00 53 55 56 57 6A 6B 58 6A 65 66 89 84 24 CC 00 00 00 33 ED 58 6A 72 59 6A 6E 5B 6A 6C 5A 6A 33 }
    condition:
        all of them
}

rule Windows_Shellcode_Rdi_918f8e2f {
    meta:
        author = "Elastic Security"
        id = "918f8e2f-c5b9-4fe2-9290-12a74b3b494e"
        fingerprint = "9793e0bcdf305237eb2920d54b524b1bc11c583612fc2e5190879eeed8e19663"
        creation_date = "2025-01-15"
        last_modified = "2025-02-11"
        threat_name = "Windows.Shellcode.Rdi"
        reference_sample = "d8dab346c6235426e6119f8eb6bf81cafda8fb8ea88b86205e34d9c369b3b746"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a64 = { E8 00 00 00 00 59 49 89 C8 BA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 56 48 89 E6 48 83 E4 F0 48 83 EC 30 48 89 4C 24 28 }
        $a32 = { E8 00 00 00 00 58 55 89 E5 89 C2 81 C2 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 E8 05 00 00 00 83 C4 14 C9 C3 }
    condition:
        any of them
}

