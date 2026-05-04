rule Linux_Trojan_Dnsamp_c31eebd4 {
    meta:
        author = "Elastic Security"
        id = "c31eebd4-7709-440d-95d1-f9a3071cc5ca"
        fingerprint = "220b656a51b3041ede4ffe8f509657c393ff100c88b401c802079aae5804dacd"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Dnsamp"
        reference_sample = "4b86de97819a49a90961d59f9c3ab9f8e57e19add9fe1237d2a2948b4ff22de6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 F8 8B 40 14 48 63 D0 48 8D 45 E0 48 8D 70 04 48 8B 45 F8 48 8B }
    condition:
        all of them
}

