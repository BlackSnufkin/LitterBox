rule Linux_Trojan_Patpooty_e2e0dff1 {
    meta:
        author = "Elastic Security"
        id = "e2e0dff1-bb01-437e-b138-7da3954dc473"
        fingerprint = "275ff92c5de2d2183ea8870b7353d24f026f358dc7d30d1a35d508a158787719"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Patpooty"
        reference_sample = "d38b9e76cbc863f69b29fc47262ceafd26ac476b0ae6283d3fa50985f93bedf3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F0 8B 45 E4 8B 34 88 8D 7E 01 FC 31 C0 83 C9 FF F2 AE F7 D1 83 }
    condition:
        all of them
}

rule Linux_Trojan_Patpooty_f90c7e43 {
    meta:
        author = "Elastic Security"
        id = "f90c7e43-0c32-487f-a7c2-8290b341019c"
        fingerprint = "b0b0fd8da224bcd1c048c5578ed487d119f9bff4fb465f77d3043cf77d904f3d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Patpooty"
        reference_sample = "79475a66be8741d9884bc60f593c81a44bdb212592cd1a7b6130166a724cb3d3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C2 48 39 C2 75 F1 C7 43 58 01 00 00 00 C7 43 54 01 00 00 00 C7 43 50 01 00 }
    condition:
        all of them
}

