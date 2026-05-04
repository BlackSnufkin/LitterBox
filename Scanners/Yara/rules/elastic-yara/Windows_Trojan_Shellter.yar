rule Windows_Trojan_Shellter_89e693fc {
    meta:
        author = "Elastic Security"
        id = "89e693fc-cdfd-48ac-8583-0754e716bb9f"
        fingerprint = "2ba7f2d4d580433d8ba9817047b92757a22fb930bf94cb14e7bb9f936d7bb87f"
        creation_date = "2025-06-30"
        last_modified = "2025-07-23"
        threat_name = "Windows.Trojan.Shellter"
        reference_sample = "c865f24e4b9b0855b8b559fc3769239b0aa6e8d680406616a13d9a36fbbc2d30"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $seq_api_hashing = { 48 8B 44 24 ?? 0F BE 00 85 C0 74 ?? 48 8B 44 24 ?? 0F BE 00 89 44 24 ?? 48 8B 44 24 ?? 48 FF C0 48 89 44 24 ?? 8B 04 24 C1 E8 ?? 8B 0C 24 C1 E1 ?? 0B C1 }
        $seq_debug = { 48 8B 49 30 8B 49 70 8B 40 74 0B C1 25 70 00 00 40 85 C0 75 22 B8 D4 02 00 00 48 05 00 00 FE 7F }
        $seq_mem_marker = { 44 89 44 24 ?? 89 54 24 ?? 48 89 4C 24 ?? 33 C0 83 F8 ?? 74 ?? 48 8B 44 24 ?? 8B 4C 24 ?? 39 08 75 ?? EB ?? 48 63 44 24 ?? 48 8B 4C 24 }
        $seq_check_jmp_rcx = { 48 89 4C 24 ?? B8 01 00 00 00 48 6B C0 00 48 8B 4C 24 ?? 0F B6 04 01 3D FF 00 00 00 75 ?? B8 01 00 00 00 48 6B C0 01 48 8B 4C 24 ?? 0F B6 04 01 3D E1 00 00 00 75 ?? B8 01 00 00 00 }
        $seq_syscall_stub = { C6 84 24 98 00 00 00 4C C6 84 24 99 00 00 00 8B C6 84 24 9A 00 00 00 D1 C6 84 24 9B 00 00 00 B8 C6 84 24 9C 00 00 00 00 C6 84 24 9D 00 00 00 00 C6 84 24 9E 00 00 00 00 }
        $seq_mem_xor = { 48 8B 4C 24 ?? 0F B6 04 01 0F B6 4C 24 ?? 3B C1 74 ?? 8B 44 24 ?? 0F B6 4C 24 ?? 48 8B 54 24 ?? 0F B6 04 02 33 C1 8B 4C 24 ?? 48 8B 54 24 ?? 88 04 0A }
        $seq_excep_handler = { 48 89 4C 24 08 48 83 EC 18 48 B8 E8 E7 E6 E5 E4 E3 E2 E1 48 89 04 24 48 8B 44 24 20 48 8B 00 81 38 05 00 00 C0 }
    condition:
        3 of them
}

rule Windows_Trojan_Shellter_623c948f {
    meta:
        author = "Elastic Security"
        id = "623c948f-f27c-46dd-9229-e9cb0589da7f"
        fingerprint = "77821228e707e42f1379720a986c6ab4c6dbccb2b8ff108c99dc770fb20a7b5b"
        creation_date = "2026-03-09"
        last_modified = "2026-03-17"
        threat_name = "Windows.Trojan.Shellter"
        reference_sample = "659c8d0fb3d70ac47527e96115062d22aabfe07a841bb8e51cafe0736b817802"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 8B 45 ?? 0F BE 08 85 C9 74 ?? 8B 55 08 0F BE 02 89 45 F8 8B 4D 08 83 C1 01 89 4D 08 8B 55 FC C1 EA 0D 8B 45 FC C1 E0 13 }
        $b = { 83 E2 ?? 81 E2 ?? 00 00 00 0F B6 C2 B9 ?? 00 00 00 2B C8 BA 04 00 00 00 6B C2 ?? 8B }
        $c = { C7 85 B0 F4 FF FF 00 00 00 00 C7 85 B4 F4 FF FF FF FF FF FF C7 85 B8 F4 FF FF 00 30 00 00 C7 85 BC F4 FF FF 04 00 00 00 8D 45 B8 }
        $d = { 8B 4D FC 8B 91 00 01 00 00 89 55 F4 8B 45 FC 8B 88 }
        $e = { 0F B6 55 FF 8B 45 ?? 03 45 ?? 0F B6 08 33 CA 8B 55 ?? 03 55 ?? 88 0A }
    condition:
        3 of them
}

