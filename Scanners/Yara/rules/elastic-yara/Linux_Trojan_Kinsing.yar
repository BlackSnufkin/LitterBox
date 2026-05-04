rule Linux_Trojan_Kinsing_196523fa {
    meta:
        author = "Elastic Security"
        id = "196523fa-2bb5-4ada-b929-ddc3d5505b73"
        fingerprint = "29fa6e4fe5cbcd5c927e6b065f3354e4e9015e65814400687b2361fc9a951c74"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Kinsing"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 64 65 38 5F 00 64 48 8B 0C 25 F8 FF FF FF 48 3B 61 10 76 35 48 83 }
    condition:
        all of them
}

rule Linux_Trojan_Kinsing_7cdbe9fa {
    meta:
        author = "Elastic Security"
        id = "7cdbe9fa-39a3-43a0-853a-16f41e20f304"
        fingerprint = "2452c2821b4ca104a18d3733ee8f6744a738aca197aa35392c480e224a5f8175"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Kinsing"
        reference_sample = "b3527e3d03a30fcf1fdaa73a1b3743866da6db088fbfa5f51964f519e22d05e6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 73 2E 72 75 22 20 7C 20 61 77 6B 20 27 7B 70 72 69 6E 74 20 }
    condition:
        all of them
}

rule Linux_Trojan_Kinsing_2c1ffe78 {
    meta:
        author = "Elastic Security"
        id = "2c1ffe78-a965-4a70-8a9c-2cad705f8be7"
        fingerprint = "6701b007ee14a022525301d53af0f4254bc26fdfbe27d3d5cebc2d40e8536ed6"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Kinsing"
        reference_sample = "b3527e3d03a30fcf1fdaa73a1b3743866da6db088fbfa5f51964f519e22d05e6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 73 74 73 20 22 24 42 49 4E 5F 46 55 4C 4C 5F 50 41 54 48 22 20 22 }
    condition:
        all of them
}

rule Linux_Trojan_Kinsing_85276fb4 {
    meta:
        author = "Elastic Security"
        id = "85276fb4-11f4-4265-9533-a96b42247f96"
        fingerprint = "966d53d8fc0e241250a861107317266ad87205d25466a4e6cdb27c3e4e613d92"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Kinsing"
        reference_sample = "b3527e3d03a30fcf1fdaa73a1b3743866da6db088fbfa5f51964f519e22d05e6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 65 5F 76 00 64 48 8B 0C 25 F8 FF FF FF 48 3B 61 10 76 38 48 83 }
    condition:
        all of them
}

