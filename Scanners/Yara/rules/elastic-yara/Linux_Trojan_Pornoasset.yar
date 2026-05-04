rule Linux_Trojan_Pornoasset_927f314f {
    meta:
        author = "Elastic Security"
        id = "927f314f-2cbb-4f87-b75c-9aa5ef758599"
        fingerprint = "7214d3132fc606482e3f6236d291082a3abc0359c80255048045dba6e60ec7bf"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Pornoasset"
        reference_sample = "d653598df857535c354ba21d96358d4767d6ada137ee32ce5eb4972363b35f93"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C3 D3 CB D3 C3 48 31 C3 48 0F AF F0 48 0F AF F0 48 0F AF F0 48 }
    condition:
        all of them
}

