rule Linux_Trojan_Cerbu_69d5657e {
    meta:
        author = "Elastic Security"
        id = "69d5657e-1fe9-4367-b478-218c278c7fbc"
        fingerprint = "7dfaebc6934c8fa97509831e0011f2befd0dbc24a68e4a07bc1ee0decae45a42"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Cerbu"
        reference_sample = "f10bf3cf2fdfbd365d3c2d8dedb2d01b85236eaa97d15370dbcb5166149d70e9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 5B 5E C9 C3 55 89 E5 83 EC 08 83 C4 FC FF 75 0C 6A 05 FF }
    condition:
        all of them
}

