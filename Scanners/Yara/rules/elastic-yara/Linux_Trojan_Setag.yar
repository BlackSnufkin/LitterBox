rule Linux_Trojan_Setag_351eeb76 {
    meta:
        author = "Elastic Security"
        id = "351eeb76-ccca-40d5-8ee3-e8daf6494dda"
        fingerprint = "c6edc7ae898831e9cc3c92fcdce4cd5b4412de061575e6da2f4e07776e0885f5"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Setag"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 04 8B 45 F8 C1 E0 02 01 C2 8B 45 EC 89 02 8D 45 F8 FF 00 8B }
    condition:
        all of them
}

rule Linux_Trojan_Setag_01e2f79b {
    meta:
        author = "Elastic Security"
        id = "01e2f79b-fcbc-41d0-a68b-3a692b893f26"
        fingerprint = "4ea87a6ccf907babdebbbb07b9bc32a5437d0213f1580ea4b4b3f44ce543a5bd"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Setag"
        reference_sample = "5b5e8486174026491341a750f6367959999bbacd3689215f59a62dbb13a45fcc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0C 8B 45 EC 89 45 FC 8D 55 E8 83 EC 04 8D 45 F8 50 8D 45 FC }
    condition:
        all of them
}

