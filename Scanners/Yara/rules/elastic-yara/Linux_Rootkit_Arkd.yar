rule Linux_Rootkit_Arkd_bbd56917 {
    meta:
        author = "Elastic Security"
        id = "bbd56917-aeab-4e73-b85b-adc41fc7ffe4"
        fingerprint = "73c8b2685b6b568575afca3c3c2fe2095d94f2040f4a1207974fe77bbb657163"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Rootkit.Arkd"
        reference_sample = "e0765f0e90839b551778214c2f9ae567dd44838516a3df2c73396a488227a600"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 7D 0B B8 FF FF FF FF EB 11 8D 74 26 00 39 C1 7F 04 31 C0 EB 05 B8 01 00 }
    condition:
        all of them
}

