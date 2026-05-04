rule Linux_Trojan_Ipstorm_3c43d4a7 {
    meta:
        author = "Elastic Security"
        id = "3c43d4a7-185a-468b-a73d-82f579de98c1"
        fingerprint = "cf6812f8f0ee7951a70bec3839b798a574d536baae4cf37cda6eebf570cab0be"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ipstorm"
        reference_sample = "5103133574615fb49f6a94607540644689be017740d17005bc08b26be9485aa7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 48 8D 54 24 58 31 F6 EB 11 48 8B 84 24 88 00 00 00 48 89 F1 48 }
    condition:
        all of them
}

rule Linux_Trojan_Ipstorm_f9269f00 {
    meta:
        author = "Elastic Security"
        id = "f9269f00-4664-47a4-9148-fa74e2cfee7c"
        fingerprint = "509de41454bcc60dad0d96448592aa20fb997ce46ad8fed5d4bbdbe2ede588d6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ipstorm"
        reference_sample = "5103133574615fb49f6a94607540644689be017740d17005bc08b26be9485aa7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EC C0 00 00 00 48 89 AC 24 B8 00 00 00 48 8D AC 24 B8 00 00 00 B8 69 00 }
    condition:
        all of them
}

rule Linux_Trojan_Ipstorm_08bcf61c {
    meta:
        author = "Elastic Security"
        id = "08bcf61c-baef-4320-885c-8f8949684dde"
        fingerprint = "348295602b1582839f6acc603832f09e9afab71731bc21742d1a638e41df6e7c"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ipstorm"
        reference_sample = "503f293d84de4f2c826f81a68180ad869e0d1448ea6c0dbf09a7b23801e1a9b9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8C 24 98 00 00 00 31 D2 31 DB EB 04 48 83 C1 18 48 8B 31 48 83 79 }
    condition:
        all of them
}

