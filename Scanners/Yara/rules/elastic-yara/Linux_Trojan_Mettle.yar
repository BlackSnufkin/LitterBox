rule Linux_Trojan_Mettle_e8fdbcbd {
    meta:
        author = "Elastic Security"
        id = "e8fdbcbd-84d3-4c42-986b-c8d5d940a96a"
        fingerprint = "2038686308a77286ed5d13b408962075933da7ca5772d46b65e5f247193036b5"
        creation_date = "2024-05-06"
        last_modified = "2024-05-21"
        threat_name = "Linux.Trojan.Mettle"
        reference_sample = "864eae4f27648b8a9d9b0eb1894169aa739311cdd02b1435a34881acf7059d58"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $mettle1 = "mettlesploit!"
        $mettle2 = "/mettle/mettle/src/"
        $mettle3 = "mettle_get_c2"
        $mettle4 = "mettle_console_start_interactive"
        $mettle5 = "mettle_get_machine_id"
    condition:
        2 of ($mettle*)
}

rule Linux_Trojan_Mettle_813b9b6c {
    meta:
        author = "Elastic Security"
        id = "813b9b6c-946d-46f0-a255-d06ab78347d4"
        fingerprint = "6b350abfda820ee4c6e7aa84f732ab4527c454b93ae13363747f024bb8c5e3b4"
        creation_date = "2024-05-06"
        last_modified = "2024-05-21"
        threat_name = "Linux.Trojan.Mettle"
        reference_sample = "bb651d974ca3f349858db7b5a86f03a8d47d668294f27e709a823fa11e6963d7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $process_set_nonblocking_stdio = { 55 89 E5 53 83 EC 08 E8 ?? ?? ?? ?? 81 C3 3D 32 0D 00 6A 00 6A 03 6A 00 E8 ?? ?? ?? ?? 83 C4 0C 80 CC 08 50 6A 04 6A 00 E8 ?? ?? ?? ?? 83 C4 0C 6A 00 6A 03 6A 01 E8 ?? ?? ?? ?? 83 C4 0C 80 CC 08 50 6A 04 6A 01 E8 }
        $process_create = { 55 89 E5 57 56 53 81 EC 98 00 00 00 E8 ?? ?? ?? ?? 81 C3 A6 3B 0D 00 89 45 84 89 95 78 FF FF FF 89 4D 80 8B 7D 0C 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 10 40 0F ?? ?? ?? ?? ?? 50 50 68 B4 00 00 00 6A 01 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 0F ?? ?? ?? ?? ?? F6 47 14 80 74 ?? 6A 00 6A 00 6A 00 8D 45 ?? 50 E8 ?? ?? ?? ?? 89 85 7C FF FF FF }
        $process_read = { 55 89 E5 57 56 53 83 EC 1C E8 ?? ?? ?? ?? 81 C3 90 30 0D 00 8B 4D 08 8B 7D 0C 8B 75 10 83 C8 FF 85 C9 74 ?? 52 56 57 FF 71 24 89 4D E4 E8 ?? ?? ?? ?? 89 C2 83 C4 10 39 C6 8B 4D E4 76 ?? 50 29 D6 56 01 D7 89 55 E4 57 FF 71 48 E8 ?? ?? ?? ?? 8B 55 E4 01 C2 83 C4 10 89 D0 8D 65 ?? 5B 5E 5F 5D C3 }
        $file_new = { 83 C4 10 52 52 50 FF 76 0C E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 83 C4 10 8D 65 ?? 5B 5E 5F 5D C3 }
        $file_read = { 55 89 E5 53 83 EC 10 E8 ?? ?? ?? ?? 81 C3 41 A7 0D 00 FF 75 08 E8 ?? ?? ?? ?? 50 FF 75 10 6A 01 FF 75 0C E8 ?? ?? ?? ?? 8B 5D FC C9 C3 }
        $file_seek = { 55 89 E5 53 83 EC 10 E8 ?? ?? ?? ?? 81 C3 C0 A6 0D 00 FF 75 08 E8 ?? ?? ?? ?? 83 C4 0C FF 75 10 FF 75 0C 50 E8 ?? ?? ?? ?? 8B 5D FC C9 C3 }
        $func_write_audio_file = { 55 89 E5 57 56 53 83 EC 18 E8 ?? ?? ?? ?? 81 C3 D8 23 0D 00 FF 75 08 E8 ?? ?? ?? ?? 89 C6 8B 45 10 03 06 89 06 5A 59 50 FF 76 04 E8 ?? ?? ?? ?? 89 C7 89 46 04 83 C4 10 83 C8 FF 85 FF 74 ?? 2B 7D 10 8B 06 01 F8 89 C7 8B 75 0C 8B 4D 10 F3 ?? 8B 45 10 8D 65 ?? 5B 5E 5F 5D C3 }
        $func_is_compatible_elf = { 55 89 E5 56 53 E8 ?? ?? ?? ?? 81 C3 CF AB 05 00 8B 55 08 31 C0 81 3A 7F 45 4C 46 75 ?? 80 7A 04 01 75 ?? 0F B6 72 05 83 EC 0C 6A 01 E8 ?? ?? ?? ?? 83 C4 10 48 0F 94 C0 0F B6 C0 40 39 C6 0F 94 C0 0F B6 C0 83 E0 01 8D 65 ?? 5B 5E 5D C3 }
        $func_stack_setup = { 89 DA 31 C0 8B 0C 86 85 C9 8D 40 ?? 74 ?? 89 0A 83 C2 04 EB ?? C7 02 00 00 00 00 C7 04 83 00 00 00 00 EB ?? 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 8B 45 DC 89 45 10 8B 45 E0 89 45 0C 89 5D 08 8D 65 ?? 5B 5E 5F 5D }
        $func_c2_new_struct = { C7 46 14 00 00 00 00 C7 46 10 00 00 00 00 C7 46 18 00 00 00 00 8D 83 ?? ?? ?? ?? 89 46 20 C7 46 24 00 00 00 00 C7 46 28 00 00 00 00 C7 46 2C 00 00 00 00 C7 46 30 00 00 F0 3F 89 76 1C 83 EC 0C 56 E8 }
    condition:
        2 of ($process*) and 2 of ($file*) and 2 of ($func*)
}

rule Linux_Trojan_Mettle_78aead1c {
    meta:
        author = "Elastic Security"
        id = "78aead1c-7dc2-4db0-a0b8-cccf2d583c67"
        fingerprint = "bf2b8bd0e12905ab4bed94c70dbd854a482446909ba255fceaee309efd69b835"
        creation_date = "2024-05-06"
        last_modified = "2024-05-21"
        threat_name = "Linux.Trojan.Mettle"
        reference_sample = "864eae4f27648b8a9d9b0eb1894169aa739311cdd02b1435a34881acf7059d58"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $process_set_nonblocking_stdio = { 48 83 EC 08 31 D2 BE 03 00 00 00 31 FF 31 C0 E8 ?? ?? ?? ?? 80 CC 08 BE 04 00 00 00 31 FF 89 C2 31 C0 E8 ?? ?? ?? ?? 31 D2 BE 03 00 00 00 BF 01 00 00 00 31 C0 E8 ?? ?? ?? ?? 80 CC 08 BE 04 00 00 00 BF 01 00 00 00 89 C2 31 C0 E8 }
        $process_create = { 41 57 41 56 49 89 CE 41 55 41 54 4D 89 C5 55 53 48 89 FB 48 89 D5 48 81 EC 88 00 00 00 48 8D ?? ?? ?? 48 89 34 24 E8 ?? ?? ?? ?? FF C0 0F ?? ?? ?? ?? ?? BE 20 01 00 00 BF 01 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 49 89 C7 0F ?? ?? ?? ?? ?? 41 F6 45 28 80 74 ?? 48 8D ?? ?? ?? 31 C9 31 D2 31 F6 E8 ?? ?? ?? ?? 85 C0 }
        $process_read = { 48 85 FF 74 ?? 41 55 41 54 49 89 FD 55 53 48 89 D5 49 89 F4 48 83 EC 08 48 8B 7F 38 E8 ?? ?? ?? ?? 48 39 C5 48 89 C3 76 ?? 49 8B 7D 70 48 89 EA 49 8D ?? ?? 48 29 C2 E8 ?? ?? ?? ?? 48 01 C3 5A 48 89 D8 5B 5D 41 5C 41 5D C3 }
        $file_new = { 41 54 55 48 89 F5 53 48 89 FB 48 8B 7F 10 BE B2 04 01 00 E8 ?? ?? ?? ?? 48 8B 7B 10 BE B3 04 01 00 49 89 C4 E8 ?? ?? ?? ?? 48 85 C0 75 ?? 48 8D ?? ?? ?? ?? ?? 48 89 C6 4C 89 E7 E8 ?? ?? ?? ?? 83 CA FF 48 85 C0 74 ?? 48 89 C6 48 89 EF E8 ?? ?? ?? ?? 31 D2 5B 89 D0 5D 41 5C C3 }
        $file_read = { 53 48 89 F3 48 83 EC 10 48 89 54 24 08 E8 ?? ?? ?? ?? 48 8B 54 24 08 48 83 C4 10 48 89 DF 5B 48 89 C1 BE 01 00 00 00 E9 }
        $file_seek = { 48 83 EC 18 48 89 74 24 08 89 54 24 04 E8 ?? ?? ?? ?? 8B 54 24 04 48 8B 74 24 08 48 89 C7 48 83 C4 18 E9 }
        $func_write_audio_file = { 41 54 55 49 89 F4 53 48 89 D3 E8 ?? ?? ?? ?? 48 8B 30 48 8B 78 08 48 89 C5 48 01 DE 48 89 30 E8 ?? ?? ?? ?? 48 89 C7 48 89 45 08 48 83 C8 FF 48 85 FF 74 ?? 48 8B 45 00 48 29 DF 4C 89 E6 48 89 D9 48 01 F8 48 89 C7 48 89 D8 F3 ?? 5B 5D 41 5C C3 }
        $func_is_compatible_elf = { 31 C0 81 3F 7F 45 4C 46 75 ?? 80 7F 04 02 75 ?? 53 0F B6 5F 05 BF 01 00 00 00 E8 ?? ?? ?? ?? FF C8 0F 94 C0 0F B6 C0 FF C0 39 C3 0F 94 C0 0F B6 C0 83 E0 01 5B C3 83 E0 01 C3 }
        $func_stack_setup = { 48 89 EA 31 C0 49 8B 0C C0 48 FF C0 48 85 C9 74 ?? 48 89 0A 48 83 C2 08 EB ?? 48 C7 02 00 00 00 00 48 C7 44 C5 00 00 00 00 00 EB ?? 48 89 EF 4C 89 4C 24 08 E8 ?? ?? ?? ?? 4C 8B 4C 24 08 48 83 C4 10 48 89 DA 48 89 EF 5B 5D 41 5C 4C 89 CE }
        $func_c2_new_struct = { 48 89 DF 48 C7 43 20 00 00 00 00 C7 43 28 00 00 00 00 48 C7 43 40 00 00 00 00 48 89 43 38 48 8B 05 D1 BE 09 00 48 89 5B 30 48 89 43 48 E8 }
    condition:
        2 of ($process*) and 2 of ($file*) and 2 of ($func*)
}

