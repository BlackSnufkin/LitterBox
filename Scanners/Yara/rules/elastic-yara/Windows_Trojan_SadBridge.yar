rule Windows_Trojan_SadBridge_6e83eaeb {
    meta:
        author = "Elastic Security"
        id = "6e83eaeb-12f8-4abd-8ad9-17f9a301a1c8"
        fingerprint = "0b53af98d044001a34779b27bc77f9d61f590826361441d93b6460fdbd1086d0"
        creation_date = "2024-11-05"
        last_modified = "2024-12-04"
        threat_name = "Windows.Trojan.SadBridge"
        reference_sample = "b432cdd217b171f3ad4a8a959fa0357bd7917f078a9546aed1649af00fc4bda6"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 81 EC A0 07 00 33 FF C7 00 45 A0 30 31 32 33 48 8B 00 DA 40 88 7D AC 0F 57 C0 09 C0 00 BC 33 A1 00 CC 8B F1 48 00 89 45 F0 48 8D 55 A0 C7 00 45 A4 34 35 36 37 48 8D 00 4D D0 C7 45 A8 38 39 }
    condition:
        all of them
}

