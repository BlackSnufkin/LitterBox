rule Linux_Trojan_Ebury_7b13e9b6 {
    meta:
        author = "Elastic Security"
        id = "7b13e9b6-ce96-4bd3-8196-83420280bd1f"
        fingerprint = "a891724ce36e86637540f722bc13b44984771f709219976168f12fe782f08306"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ebury"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 44 24 10 4C 8B 54 24 18 4C 8B 5C 24 20 8B 5C 24 28 74 04 }
    condition:
        all of them
}

