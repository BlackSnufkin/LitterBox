rule Windows_Trojan_Lokibot_1f885282 {
    meta:
        author = "Elastic Security"
        id = "1f885282-b60e-491e-ae1b-d26825e5aadb"
        fingerprint = "a7519bb0751a6c928af7548eaed2459e0ed26128350262d1278f74f2ad91331b"
        creation_date = "2021-06-22"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Lokibot"
        reference_sample = "916eded682d11cbdf4bc872a8c1bcaae4d4e038ac0f869f59cc0a83867076409"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "MAC=%02X%02X%02XINSTALL=%08X%08Xk" fullword
    condition:
        all of them
}

rule Windows_Trojan_Lokibot_0f421617 {
    meta:
        author = "Elastic Security"
        id = "0f421617-df2b-4cb5-9d10-d984f6553012"
        fingerprint = "9ff5d594428e4a5de84f0142dfa9f54cb75489192461deb978c70f1bdc88acda"
        creation_date = "2021-07-20"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Lokibot"
        reference_sample = "de6200b184832e7d3bfe00c193034192774e3cfca96120dc97ad6fed1e472080"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 08 8B CE 0F B6 14 38 D3 E2 83 C1 08 03 F2 48 79 F2 5F 8B C6 }
    condition:
        all of them
}

