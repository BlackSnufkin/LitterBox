rule Linux_Trojan_Ganiw_99349371 {
    meta:
        author = "Elastic Security"
        id = "99349371-644e-4954-9b7d-f2f579922565"
        fingerprint = "6b0cbea419915567c2ecd84bfcb2c7f7301435ee953f16c6dcba826802637551"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ganiw"
        reference_sample = "e8dbb246fdd1a50226a36c407ac90eb44b0cf5e92bf0b92c89218f474f9c2afb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 66 89 43 02 8B 5D FC C9 C3 55 89 E5 53 83 EC 04 8B 45 14 8B }
    condition:
        all of them
}

rule Linux_Trojan_Ganiw_b9f045aa {
    meta:
        author = "Elastic Security"
        id = "b9f045aa-99fa-47e9-b179-ac62158b3fe2"
        fingerprint = "0aaec92ca1c622df848bba80a2f1e4646252625d58e28269965b13d65158f238"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Ganiw"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E5 57 8B 55 0C 85 D2 74 21 FC 31 C0 8B 7D 08 AB AB AB AB AB AB }
    condition:
        all of them
}

