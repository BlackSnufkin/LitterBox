rule MacOS_Trojan_Getshell_f339d74c {
    meta:
        author = "Elastic Security"
        id = "f339d74c-36f1-46e5-bf7d-22f49a0948a5"
        fingerprint = "fad5ca4f345c2c01a3d222f59bac8d5dacf818d4e018c8d411d86266a481a1a1"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Getshell"
        reference_sample = "b2199c15500728a522c04320aee000938f7eb69d751a55d7e51a2806d8cd0fe7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 00 00 FF E0 E8 00 00 00 00 58 8B 80 4B 22 00 00 FF E0 55 89 E5 53 83 EC 04 E8 }
    condition:
        all of them
}

