rule Windows_Trojan_Formbook_1112e116 {
    meta:
        author = "Elastic Security"
        id = "1112e116-dee0-4818-a41f-ca5c1c41b4b8"
        fingerprint = "b8b88451ad8c66b54e21455d835a5d435e52173c86e9b813ffab09451aff7134"
        creation_date = "2021-06-14"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Formbook"
        reference = "https://www.elastic.co/security-labs/formbook-adopts-cab-less-approach"
        reference_sample = "6246f3b89f0e4913abd88ae535ae3597865270f58201dc7f8ec0c87f15ff370a"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 3C 30 50 4F 53 54 74 09 40 }
        $a2 = { 74 0A 4E 0F B6 08 8D 44 08 01 75 F6 8D 70 01 0F B6 00 8D 55 }
        $a3 = { 1A D2 80 E2 AF 80 C2 7E EB 2A 80 FA 2F 75 11 8A D0 80 E2 01 }
        $a4 = { 04 83 C4 0C 83 06 07 5B 5F 5E 8B E5 5D C3 8B 17 03 55 0C 6A 01 83 }
    condition:
        any of them
}

rule Windows_Trojan_Formbook_772cc62d {
    meta:
        author = "Elastic Security"
        id = "772cc62d-345c-42d8-97ab-f67e447ddca4"
        fingerprint = "3d732c989df085aefa1a93b38a3c078f9f0c3ee214292f6c1e31a9fc1c9ae50e"
        creation_date = "2022-05-23"
        last_modified = "2022-07-18"
        threat_name = "Windows.Trojan.Formbook"
        reference = "https://www.elastic.co/security-labs/formbook-adopts-cab-less-approach"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko"
        $a2 = "signin"
        $a3 = "persistent"
        $r1 = /.\:\\Users\\[^\\]{1,50}\\AppData\\Roaming\\[a-zA-Z0-9]{8}\\[a-zA-Z0-9]{3}log\.ini/ wide
    condition:
        2 of ($a*) and $r1
}

rule Windows_Trojan_Formbook_5799d1f2 {
    meta:
        author = "Elastic Security"
        id = "5799d1f2-4d4f-49d6-b010-67d2fbc04824"
        fingerprint = "b262c4223e90c539c73831f7f833d25fe938eaecb77ca6d2e93add6f93e7d75d"
        creation_date = "2022-06-08"
        last_modified = "2022-09-29"
        threat_name = "Windows.Trojan.Formbook"
        reference = "https://www.elastic.co/security-labs/formbook-adopts-cab-less-approach"
        reference_sample = "8555a6d313cb17f958fc2e08d6c042aaff9ceda967f8598ac65ab6333d14efd9"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { E9 C5 9C FF FF C3 E8 00 00 00 00 58 C3 68 }
    condition:
        all of them
}

rule Windows_Trojan_Formbook_999a203e {
    meta:
        author = "Elastic Security"
        id = "999a203e-70ec-4100-ab3f-23e99b00041c"
        fingerprint = "61544f5c38d3f0cca7a867c973fd1ba713a187f63b25364b51fb0290221d21a4"
        creation_date = "2025-09-09"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.Formbook"
        reference_sample = "fe6b659e6a6d19470cf5cfb5dfef263d22119463a6d084c31006c24c0045bd72"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 8D 44 37 FE 8D 4E FF 8A 50 01 28 10 48 49 75 ?? 83 FE 01 76 ?? 8B C7 8D 4E FF 8D 9B 00 00 00 00 8A 50 01 28 10 40 49 }
        $b = { B8 90 90 90 90 89 07 66 89 47 04 8D 5F 06 BF 04 00 00 00 39 7D FC 76 }
        $c = { B2 88 81 3C 31 40 41 49 48 75 ?? 80 7C 31 04 B8 75 ?? 38 54 31 05 }
        $d = { 8D 57 FD 52 C7 45 14 90 90 90 90 C7 45 F8 55 8B EC 00 C7 45 FC 00 00 00 00 }
    condition:
        3 of them
}

