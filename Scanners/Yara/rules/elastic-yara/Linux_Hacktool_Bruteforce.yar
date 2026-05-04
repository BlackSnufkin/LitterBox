rule Linux_Hacktool_Bruteforce_bad95bd6 {
    meta:
        author = "Elastic Security"
        id = "bad95bd6-94a9-4abf-9d3b-781f0b79c5ce"
        fingerprint = "10698122ff9fe06b398307ec15ad4f5bb519285e1eaad97011abf0914f1e7afd"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Bruteforce"
        reference_sample = "8e8be482357ebddc6ac3ea9ee60241d011063f7e558a59e6bd119e72e4862024"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 73 65 6E 64 6D 6D 73 67 00 66 70 75 74 73 00 6D 65 6D 63 70 79 00 }
    condition:
        all of them
}

rule Linux_Hacktool_Bruteforce_66a14c03 {
    meta:
        author = "Elastic Security"
        id = "66a14c03-f4a3-4b24-a5db-5a9235334e37"
        fingerprint = "255c1a2e781ff7f330c09b3c82f08db110579f77ccef8780d03e9aa3eec86607"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Bruteforce"
        reference_sample = "a2d8e2c34ae95243477820583c0b00dfe3f475811d57ffb95a557a227f94cd55"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 8B 4C 24 08 78 3D 48 8B 44 24 30 48 29 C8 48 89 4D 08 48 89 }
    condition:
        all of them
}

rule Linux_Hacktool_Bruteforce_eb83b6aa {
    meta:
        author = "Elastic Security"
        id = "eb83b6aa-d7b5-4d10-9258-4bf619fc6582"
        fingerprint = "7767bf57c57d398f27646f5ae2bcda07d6c62959becb31a5186ff0b027ff02b4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Hacktool.Bruteforce"
        reference_sample = "8dec88576f61f37fbaece3c30e71d338c340c8fb9c231f9d7b1c32510d2c3167"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 89 45 EC EB 04 83 6D EC 01 83 7D EC 00 74 12 8B 45 EC 8D }
    condition:
        all of them
}

