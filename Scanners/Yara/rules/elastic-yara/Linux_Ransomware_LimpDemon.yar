rule Linux_Ransomware_LimpDemon_95c748e0 {
    meta:
        author = "Elastic Security"
        id = "95c748e0-e2f5-4997-a69d-dbc8885e6f18"
        fingerprint = "20527c2e0d2e577c17da7184193ba372027cedb075f78bb75aff9d218c2d660b"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.LimpDemon"
        reference_sample = "a4200e90a821a2f2eb3056872f06cf5b057be154dcc410274955b2aaca831651"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "[-] You have to pass access key to start process" fullword
        $a2 = "[+] Shutting down VMWare ESXi servers..." fullword
        $a3 = "%s --daemon (start as a service)" fullword
        $a4 = "%s --access-key <key> (key for decryption config)" fullword
    condition:
        2 of them
}

