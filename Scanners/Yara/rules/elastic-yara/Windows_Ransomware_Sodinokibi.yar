rule Windows_Ransomware_Sodinokibi_83f05fbe : beta {
    meta:
        author = "Elastic Security"
        id = "83f05fbe-65d1-423f-98df-21692167a1d6"
        fingerprint = "8c32ca099c9117e394379c0cc4771a15e5e4cfb1a98210c288e743a6d9cc9967"
        creation_date = "2020-06-18"
        last_modified = "2021-08-23"
        description = "Identifies SODINOKIBI/REvil ransomware"
        threat_name = "Windows.Ransomware.Sodinokibi"
        reference = "https://www.elastic.co/security-labs/ransomware-interrupted-sodinokibi-and-the-supply-chain"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.revil"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $d1 = { 03 C0 01 47 30 11 4F 34 01 57 30 8B 57 78 8B C2 11 77 34 8B 77 7C 8B CE 0F A4 C1 04 C1 E0 04 01 47 28 8B C2 11 4F 2C 8B CE 0F A4 C1 01 03 C0 01 47 28 11 4F 2C 01 57 28 8B 57 70 8B C2 11 77 2C 8B 77 74 8B CE 0F A4 C1 04 C1 E0 04 01 47 20 8B C2 11 4F 24 8B CE 0F A4 C1 01 03 C0 01 47 20 11 4F 24 01 57 20 8B 57 68 8B C2 11 77 24 8B 77 6C 8B CE 0F A4 C1 04 C1 E0 04 01 47 18 8B C2 11 4F 1C 8B CE 0F A4 C1 01 03 C0 01 47 18 11 4F 1C 01 57 18 8B 57 60 8B C2 11 77 1C 8B 77 64 }
        $d2 = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B 65 78 70 61 6E 64 20 31 36 2D 62 79 74 65 20 6B }
        $d3 = { F7 6F 38 03 C8 8B 43 48 13 F2 F7 6F 20 03 C8 8B 43 38 13 F2 F7 6F 30 03 C8 8B 43 40 13 F2 F7 6F 28 03 C8 8B 43 28 13 F2 F7 6F 40 03 C8 8B 45 08 13 F2 89 48 68 89 70 6C 8B 43 38 F7 6F 38 8B C8 8B F2 8B 43 28 F7 6F 48 03 C8 13 F2 8B 43 48 F7 6F 28 03 C8 8B 43 30 13 F2 F7 6F 40 0F A4 CE 01 03 C9 03 C8 8B 43 40 13 F2 F7 6F 30 03 C8 8B 45 08 13 F2 89 48 70 89 70 74 8B 43 38 F7 6F 40 8B C8 }
        $d4 = { 33 C0 8B 5A 68 8B 52 6C 0F A4 FE 08 C1 E9 18 0B C6 C1 E7 08 8B 75 08 0B CF 89 4E 68 8B CA 89 46 6C 33 C0 8B 7E 60 8B 76 64 0F A4 DA 19 C1 E9 07 0B C2 C1 E3 19 8B 55 08 0B CB 89 4A 60 8B CF 89 42 64 33 C0 8B 5A 10 8B 52 14 0F AC F7 15 C1 E1 0B C1 EE 15 0B C7 0B CE 8B 75 }
        $d5 = { C1 01 C1 EE 1F 0B D1 03 C0 0B F0 8B C2 33 43 24 8B CE 33 4B 20 33 4D E4 33 45 E0 89 4B 20 8B CB 8B 5D E0 89 41 24 8B CE 33 4D E4 8B C2 31 4F 48 33 C3 8B CF 31 41 4C 8B C7 8B CE 33 48 70 8B C2 33 47 74 33 4D E4 33 C3 89 4F 70 8B CF 89 41 74 8B }
        $d6 = { 8B 43 40 F7 6F 08 03 C8 8B 03 13 F2 F7 6F 48 03 C8 8B 43 48 13 F2 F7 2F 03 C8 8B 43 08 13 F2 F7 6F 40 03 C8 8B 43 30 13 F2 F7 6F 18 03 C8 8B 43 18 13 F2 F7 6F 30 03 C8 8B 43 38 13 F2 F7 6F 10 03 C8 8B 43 10 13 F2 F7 6F 38 03 C8 8B 43 28 13 F2 }
        $d7 = { 8B CE 33 4D F8 8B C2 33 C3 31 4F 18 8B CF 31 41 1C 8B C7 8B CE 33 48 40 8B C2 33 4D F8 33 47 44 89 4F 40 33 C3 8B CF 89 41 44 8B C7 8B CE 33 48 68 8B C2 33 47 6C 33 4D F8 33 C3 89 4F 68 8B CF 89 41 6C 8B CE 8B }
        $d8 = { 36 7D 49 30 85 35 C2 C3 68 60 4B 4B 7A BE 83 53 AB E6 8E 42 F9 C6 62 A5 D0 6A AD C6 F1 7D F6 1D 79 CD 20 FC E7 3E E1 B8 1A 43 38 12 C1 56 28 1A 04 C9 22 55 E0 D7 08 BB 9F 0B 1F 1C B9 13 06 35 }
        $d9 = { C2 C1 EE 03 8B 55 08 0B CE 89 4A 4C 8B CF 89 42 48 33 C0 8B 72 30 8B 52 34 C1 E9 0C 0F A4 DF 14 0B C7 C1 E3 14 8B 7D 08 0B CB 89 4F 30 8B CE 89 47 34 33 C0 C1 E1 0C 0F AC D6 14 0B C6 C1 EA 14 89 47 08 0B CA }
        $d10 = { 8B F2 8B 43 38 F7 6F 28 03 C8 8B 43 18 13 F2 F7 6F 48 03 C8 8B 43 28 13 F2 F7 6F 38 03 C8 8B 43 40 13 F2 F7 6F 20 0F A4 CE 01 03 C9 03 C8 8B 43 20 13 F2 F7 6F 40 03 C8 8B 43 30 13 F2 F7 6F 30 03 C8 }
        $d11 = { 33 45 FC 31 4B 28 8B CB 31 41 2C 8B CE 8B C3 33 48 50 8B C2 33 43 54 33 CF 33 45 FC 89 4B 50 8B CB 89 41 54 8B CE 8B C3 33 48 78 8B C2 33 43 7C 33 CF 33 45 FC 89 4B 78 8B CB 89 41 7C 33 B1 A0 }
        $d12 = { 52 24 0F A4 FE 0E C1 E9 12 0B C6 C1 E7 0E 8B 75 08 0B CF 89 4E 20 8B CA 89 46 24 33 C0 8B 7E 78 8B 76 7C 0F A4 DA 1B C1 E9 05 0B C2 C1 E3 1B 8B 55 08 0B CB 89 4A 78 8B CF 89 42 7C 33 C0 8B 9A }
        $d13 = { F2 8B 43 38 F7 6F 20 03 C8 8B 43 40 13 F2 F7 6F 18 03 C8 8B 43 10 13 F2 F7 6F 48 03 C8 8B 43 28 13 F2 F7 6F 30 03 C8 8B 43 20 13 F2 F7 6F 38 03 C8 8B 43 30 13 F2 F7 6F 28 03 C8 8B 43 48 13 F2 }
        $d14 = { 8B 47 30 13 F2 F7 6F 40 03 C8 13 F2 0F A4 CE 01 89 73 74 03 C9 89 4B 70 8B 47 30 F7 6F 48 8B C8 8B F2 8B 47 38 F7 6F 40 03 C8 13 F2 0F A4 CE 01 89 73 7C 03 C9 89 4B 78 8B 47 38 F7 6F 48 8B C8 }
    condition:
        all of them
}

rule Windows_Ransomware_Sodinokibi_182b2cea : beta {
    meta:
        author = "Elastic Security"
        id = "182b2cea-5aae-443a-9a2e-b3121a0ac8c7"
        fingerprint = "b71d862f6d45b388a106bf694e2bf5b4e4d78649c396e89bda46eab4206339fe"
        creation_date = "2020-06-18"
        last_modified = "2021-10-04"
        description = "Identifies SODINOKIBI/REvil ransomware"
        threat_name = "Windows.Ransomware.Sodinokibi"
        reference = "https://www.elastic.co/security-labs/ransomware-interrupted-sodinokibi-and-the-supply-chain"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.revil"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "expand 32-byte kexpand 16-byte k" ascii fullword
        $b1 = "ServicesActive" wide fullword
        $b2 = "CreateThread" ascii fullword
        $b3 = "GetExitCodeProcess" ascii fullword
        $b4 = "CloseHandle" ascii fullword
        $b5 = "SetErrorMode" ascii fullword
        $b6 = ":!:(:/:6:C:\\:m:" ascii fullword
    condition:
        ($a1 and 6 of ($b*))
}

rule Windows_Ransomware_Sodinokibi_a282ba44 : beta {
    meta:
        author = "Elastic Security"
        id = "a282ba44-b8bf-4fcc-a1c4-795675a928de"
        fingerprint = "07f1feb22f8b9de0ebd5c4649545eb4823a274b49b2c61a44d3eed4739ecd572"
        creation_date = "2020-06-18"
        last_modified = "2021-08-23"
        description = "Identifies SODINOKIBI/REvil ransomware"
        threat_name = "Windows.Ransomware.Sodinokibi"
        reference = "https://www.elastic.co/security-labs/ransomware-interrupted-sodinokibi-and-the-supply-chain"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.revil"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $c1 = { 59 59 85 F6 74 25 8B 55 08 83 66 04 00 89 3E 8B 0A 0B 4A 04 }
        $c2 = { 8D 45 F8 89 75 FC 50 8D 45 FC 89 75 F8 50 56 56 6A 01 6A 30 }
        $c3 = { 75 0C 72 D3 33 C0 40 5F 5E 5B 8B E5 5D C3 33 C0 EB F5 55 8B EC 83 }
        $c4 = { 0C 8B 04 B0 83 78 04 05 75 1C FF 70 08 FF 70 0C FF 75 0C FF }
        $c5 = { FB 8B 45 FC 50 8B 08 FF 51 08 5E 8B C7 5F 5B 8B E5 5D C3 55 }
        $c6 = { BC 00 00 00 33 D2 8B 4D F4 8B F1 8B 45 F0 0F A4 C1 01 C1 EE 1F }
        $c7 = { 54 8B CE F7 D1 8B C2 23 4D DC F7 D0 33 4D F4 23 C7 33 45 E8 89 }
        $c8 = { 0C 89 46 0C 85 C0 75 2A 33 C0 EB 6C 8B 46 08 85 C0 74 62 6B }
    condition:
        (6 of ($c*))
}

