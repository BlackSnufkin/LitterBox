rule MacOS_Trojan_Amcleaner_445bb666 {
    meta:
        author = "Elastic Security"
        id = "445bb666-1707-4ad9-a409-4a21de352957"
        fingerprint = "355c7298a4148be3b80fd841b483421bde28085c21c00d5e4a42949fd8026f5b"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Amcleaner"
        reference_sample = "c85bf71310882bc0c0cf9b74c9931fd19edad97600bc86ca51cf94ed85a78052"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 10 A0 5B 15 57 A8 8B 17 02 F9 A8 9B E8 D5 8C 96 A7 48 42 91 E5 EC 3D C8 AC 52 }
    condition:
        all of them
}

rule MacOS_Trojan_Amcleaner_a91d3907 {
    meta:
        author = "Elastic Security"
        id = "a91d3907-5e24-46c0-90ef-ed7f46ad8792"
        fingerprint = "c020567fde77a72d27c9c06f6ebb103f910321cc7a1c3b227e0965b079085b49"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Amcleaner"
        reference_sample = "dc9c700f3f6a03ecb6e3f2801d4269599c32abce7bc5e6a1b7e6a64b0e025f58"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 40 22 4E 53 49 6D 61 67 65 56 69 65 77 22 2C 56 69 6E 6E 76 63 6A 76 64 69 5A }
    condition:
        all of them
}

rule MacOS_Trojan_Amcleaner_8ce3fea8 {
    meta:
        author = "Elastic Security"
        id = "8ce3fea8-3cc7-4c59-b07c-a6dda0bb6b85"
        fingerprint = "e156d3c7a55cae84481df644569d1c5760e016ddcc7fd05d0f88fa8f9f9ffdae"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Amcleaner"
        reference_sample = "c85bf71310882bc0c0cf9b74c9931fd19edad97600bc86ca51cf94ed85a78052"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 54 40 22 4E 53 54 61 62 6C 65 56 69 65 77 22 2C 56 69 6E 6E 76 63 6B 54 70 51 }
    condition:
        all of them
}

