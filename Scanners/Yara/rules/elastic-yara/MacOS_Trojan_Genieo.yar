rule MacOS_Trojan_Genieo_5e0f8980 {
    meta:
        author = "Elastic Security"
        id = "5e0f8980-1789-4763-9e41-a521bdb3ff34"
        fingerprint = "f0b5198ce85d19889052a7e33fb7cf32a7725c4fdb384ffa7d60d209a7157092"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Genieo"
        reference_sample = "6c698bac178892dfe03624905256a7d9abe468121163d7507cade48cf2131170"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 00 CD 01 1E 68 57 58 D7 56 7C 62 C9 27 3C C6 15 A9 3D 01 02 2F E1 69 B5 4A 11 }
    condition:
        all of them
}

rule MacOS_Trojan_Genieo_37878473 {
    meta:
        author = "Elastic Security"
        id = "37878473-b6f8-4cbe-ba70-31ecddf41c82"
        fingerprint = "e9760bda6da453f75e543c919c260a4560989f62f3332f28296283d4c01b62a2"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Genieo"
        reference_sample = "0fadd926f8d763f7f15e64f857e77f44a492dcf5dc82ae965d3ddf80cd9c7a0d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 65 72 6E 61 6C 44 6F 77 6E 4C 6F 61 64 55 72 6C 46 6F 72 42 72 61 6E 64 3A 5D }
    condition:
        all of them
}

rule MacOS_Trojan_Genieo_0d003634 {
    meta:
        author = "Elastic Security"
        id = "0d003634-8b17-4e26-b4a2-4bfce2e64dde"
        fingerprint = "6f38b7fc403184482449957aff51d54ac9ea431190c6f42c7a5420efbfdb8f7d"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Genieo"
        reference_sample = "bcd391b58338efec4769e876bd510d0c4b156a7830bab56c3b56585974435d70"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 75 69 6C 64 2F 41 6E 61 62 65 6C 50 61 63 6B 61 67 65 2F 62 75 69 6C 64 2F 73 }
    condition:
        all of them
}

rule MacOS_Trojan_Genieo_9e178c0b {
    meta:
        author = "Elastic Security"
        id = "9e178c0b-02ca-499b-93d1-2b6951d41435"
        fingerprint = "b00bffbdac79c5022648bf8ca5a238db7e71f3865a309f07d068ee80ba283b82"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Genieo"
        reference_sample = "b7760e73195c3ea8566f3ff0427d85d6f35c6eec7ee9184f3aceab06da8845d8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 4D 49 70 67 41 59 4B 6B 42 5A 59 53 65 4D 6B 61 70 41 42 48 4D 5A 43 63 44 44 }
    condition:
        all of them
}

