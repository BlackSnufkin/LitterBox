rule MacOS_Trojan_SugarLoader_e7e1d99c {
    meta:
        author = "Elastic Security"
        id = "e7e1d99c-355e-4672-9176-d9eb5d2729c4"
        fingerprint = "cfffdab1e603518df48719266f0a2e91763e5ae7c033d4bf7a4c37232aa8eb04"
        creation_date = "2023-10-24"
        last_modified = "2023-10-24"
        description = "Identifies unpacked SugarLoader sample"
        threat_name = "MacOS.Trojan.SugarLoader"
        reference_sample = "3ea2ead8f3cec030906dcbffe3efd5c5d77d5d375d4a54cca03bfe8a6cb59940"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $seq_process_key = { 44 0F B6 0C 0F 89 C8 99 F7 BF ?? ?? ?? ?? 0F B6 84 17 ?? ?? ?? ?? 4C 21 C6 4C 01 CE 48 01 C6 }
        $seq_handshake = { E8 ?? ?? ?? ?? 4C 8D 75 ?? 48 89 DF 4C 89 F6 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 41 8B 06 C1 C0 ?? 44 21 F8 4C 8D 75 ?? 41 89 06 48 89 DF 4C 89 F6 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? }
        $seq_config = { 48 89 F7 48 C1 E7 05 48 29 F7 48 0F BE D1 48 01 FA 89 D6 8A 08 48 FF C0 84 C9 75 ?? EB ?? }
        $seq_recieve_msg = { 45 85 FF 74 ?? 45 39 EF BA ?? ?? ?? ?? 41 0F 42 D7 41 8B 3C 24 48 89 DE 31 C9 E8 ?? ?? ?? ?? 41 29 C7 48 01 C3 48 85 C0 7F ?? B8 ?? ?? ?? ?? EB ?? }
    condition:
        3 of ($seq*)
}

