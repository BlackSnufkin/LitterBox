rule Windows_Trojan_DBatLoader_f93a8e90 {
    meta:
        author = "Elastic Security"
        id = "f93a8e90-10ac-44de-ac3b-c0e976628e98"
        fingerprint = "81b87663fbad9854430e5c4dcade464a15b995e645f9993a3e234593ee4df901"
        creation_date = "2022-03-11"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.DBatLoader"
        reference_sample = "f72d7e445702bbf6b762ebb19d521452b9c76953d93b4d691e0e3e508790256e"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { FF 00 74 17 8B 45 E8 0F B6 7C 18 FF 66 03 7D EC 66 0F AF 7D F4 66 03 }
    condition:
        all of them
}

