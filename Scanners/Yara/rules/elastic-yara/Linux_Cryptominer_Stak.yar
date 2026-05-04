rule Linux_Cryptominer_Stak_05088561 {
    meta:
        author = "Elastic Security"
        id = "05088561-ec73-4068-a7f3-3eff612ecd28"
        fingerprint = "dfcfa99a2924eb9e8bc0e7b51db6d1b633e742e34add40dc5d1bb90375f85f6e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Stak"
        reference_sample = "d0d2bab33076121cf6a0a2c4ff1738759464a09ae4771c39442a865a76daff59"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { CD 49 8D 4D 07 48 83 E1 F8 48 39 CD 73 55 49 8B 06 48 8B 50 08 48 8D }
    condition:
        all of them
}

rule Linux_Cryptominer_Stak_ae8b98a9 {
    meta:
        author = "Elastic Security"
        id = "ae8b98a9-cc25-4606-a775-1129e0f08c3b"
        fingerprint = "0b5da501c97f53ecd79d708d898d4f5baae3c5fd80a4c39b891a952c0bcc86e5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Stak"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D1 73 5A 49 8B 06 48 8B 78 08 4C 8B 10 4C 8D 4F 18 4D 89 CB 49 }
    condition:
        all of them
}

rule Linux_Cryptominer_Stak_d707fd3a {
    meta:
        author = "Elastic Security"
        id = "d707fd3a-41ce-4f88-ad42-d663094db5fb"
        fingerprint = "c218a3c637f58a6e0dc2aa774eb681757c94e1d34f622b4ee5520985b893f631"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Stak"
        reference_sample = "d0d2bab33076121cf6a0a2c4ff1738759464a09ae4771c39442a865a76daff59"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C2 01 48 89 10 49 8B 55 00 48 8B 02 48 8B 4A 10 48 39 C8 74 9E 80 }
    condition:
        all of them
}

rule Linux_Cryptominer_Stak_52dc7af3 {
    meta:
        author = "Elastic Security"
        id = "52dc7af3-a742-4307-a5ae-c929fede1cc4"
        fingerprint = "330262703d3fcdd8b2c217db552f07e19f5df4d6bf115bfa291bb1c7f802ad97"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Stak"
        reference_sample = "a9c14b51f95d0c368bf90fb10e7d821a2fbcc79df32fd9f068a7fc053cbd7e83"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F9 48 89 D3 4D 8B 74 24 20 48 8D 41 01 4C 29 FB 4C 8D 6B 10 48 }
    condition:
        all of them
}

rule Linux_Cryptominer_Stak_bb3153ac {
    meta:
        author = "Elastic Security"
        id = "bb3153ac-b11b-4e84-afab-05dab61424ae"
        fingerprint = "c4c33125a1fad9ff393138b333a8cebfd67217e90780c45f73f660ed1fd02753"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Stak"
        reference_sample = "5b974b6e6a239bcdc067c53cc8a6180c900052d7874075244dc49aaaa9414cca"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6C 77 61 79 73 22 2C 20 22 6E 6F 5F 6D 6C 63 6B 22 2C 20 22 }
    condition:
        all of them
}

