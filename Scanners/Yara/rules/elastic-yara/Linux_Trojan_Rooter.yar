rule Linux_Trojan_Rooter_c8d08d3a {
    meta:
        author = "Elastic Security"
        id = "c8d08d3a-ff9c-4545-9f09-45fbe5b534f3"
        fingerprint = "2a09f9fabfefcf44c71ee17b823396991940bedd7a481198683ee3e88979edf4"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rooter"
        reference_sample = "f55e3aa4d875d8322cdd7caa17aa56e620473fe73c9b5ae0e18da5fbc602a6ba"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { D8 DC 04 08 BB 44 C3 04 08 CD 80 C7 05 48 FB 04 }
    condition:
        all of them
}

