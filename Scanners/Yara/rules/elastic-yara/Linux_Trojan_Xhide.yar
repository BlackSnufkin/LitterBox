rule Linux_Trojan_Xhide_7f0a131b {
    meta:
        author = "Elastic Security"
        id = "7f0a131b-c305-4a08-91cc-ac2de4d95b19"
        fingerprint = "767f2ea258cccc9f9b6673219d83e74da1d59f6847161791c9be04845f17d8cb"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xhide"
        reference_sample = "0dc35f1a1fe1c59e454cd5645f3a6220b7d85661437253a3e627eed04eca2560"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 85 68 FF FF FF 83 E0 40 85 C0 75 1A 8B 85 68 FF FF FF 83 }
    condition:
        all of them
}

rule Linux_Trojan_Xhide_cd8489f7 {
    meta:
        author = "Elastic Security"
        id = "cd8489f7-795f-4fd5-b9a6-03ddd0f3bad4"
        fingerprint = "30b2e0a8ad2fdaa040d748d8660477ae93a6ebc89a186029ff20392f6c968578"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xhide"
        reference_sample = "0dc35f1a1fe1c59e454cd5645f3a6220b7d85661437253a3e627eed04eca2560"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 6F 74 2E 63 6F 6E 66 0A 0A 00 46 75 6C 6C 20 70 61 74 68 20 }
    condition:
        all of them
}

rule Linux_Trojan_Xhide_840b27c7 {
    meta:
        author = "Elastic Security"
        id = "840b27c7-191f-4d31-9b46-f22be634b2af"
        fingerprint = "f1281db9a49986e23ef1fd9a97785d3bd7c9b3b855cf7e51744487242dd395a3"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Xhide"
        reference_sample = "0dc35f1a1fe1c59e454cd5645f3a6220b7d85661437253a3e627eed04eca2560"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 45 98 83 E0 40 85 C0 75 16 8B 45 98 83 E0 08 85 C0 75 0C 8B }
    condition:
        all of them
}

