rule Linux_Trojan_Marut_47af730d {
    meta:
        author = "Elastic Security"
        id = "47af730d-1e03-4d27-9661-84fb12b593bd"
        fingerprint = "4429ef9925aff797ab973f9a5b0efc160a516f425e3b024f22e5a5ddad26c341"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Marut"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 89 34 24 FF D1 8B 44 24 0C 0F B6 4C 24 04 8B 54 24 08 85 D2 }
    condition:
        all of them
}

