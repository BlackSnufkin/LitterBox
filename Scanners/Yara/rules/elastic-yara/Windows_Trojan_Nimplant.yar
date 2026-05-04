rule Windows_Trojan_Nimplant_44ff3211 {
    meta:
        author = "Elastic Security"
        id = "44ff3211-1ba6-4c46-a990-b2419d88367e"
        fingerprint = "cb7f823b1621e49ffac42e8a3f90ca7f8bac7ae108ca20b9a0884548681d1f87"
        creation_date = "2023-06-23"
        last_modified = "2023-07-10"
        threat_name = "Windows.Trojan.Nimplant"
        reference_sample = "b56e20384f98e1d2417bb7dcdbfb375987dd075911b74ea7ead082494836b8f4"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "@NimPlant v"
        $a2 = ".Env_NimPlant."
        $a3 = "NimPlant.dll"
    condition:
        2 of them
}

