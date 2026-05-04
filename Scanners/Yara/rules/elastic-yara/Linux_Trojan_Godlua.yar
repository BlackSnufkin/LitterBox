rule Linux_Trojan_Godlua_ed8e6228 {
    meta:
        author = "Elastic Security"
        id = "ed8e6228-d5be-4b8e-8dc2-7072b1236bfa"
        fingerprint = "9b73c2bbbe1bc43ae692f03b19cd23ad701f0120dff0201dd2a6722c44ea51ed"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Godlua"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C0 18 48 89 45 E8 EB 60 48 8B 85 58 FF FF FF 48 83 C0 20 48 89 }
    condition:
        all of them
}

