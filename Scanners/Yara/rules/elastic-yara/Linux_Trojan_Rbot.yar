rule Linux_Trojan_Rbot_c69475e3 {
    meta:
        author = "Elastic Security"
        id = "c69475e3-59eb-4d3c-9ee6-01ae7a3973d3"
        fingerprint = "593ff388ba10d66b97b5dfc9220bbda6b1584fe73d6bf7c1aa0f5391bb87e939"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rbot"
        reference_sample = "9d97c69b65d2900c39ca012fe0486e6a6abceebb890cbb6d2e091bb90f6b9690"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 56 8B 76 20 03 F5 33 C9 49 41 AD 33 DB 36 0F BE 14 28 38 F2 }
    condition:
        all of them
}

rule Linux_Trojan_Rbot_96625c8c {
    meta:
        author = "Elastic Security"
        id = "96625c8c-897c-4bf0-97e7-0dc04595cb94"
        fingerprint = "5dfabf693c87742ffa212573dded84a2c341628b79c7d11c16be493957c71a69"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rbot"
        reference_sample = "a052cfad3034d851c6fad62cc8f9c65bceedc73f3e6a37c9befe52720fd0890e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 24 28 8B 45 3C 8B 54 05 78 01 EA 8B 4A 18 8B 5A 20 01 EB E3 38 49 8B }
    condition:
        all of them
}

rule Linux_Trojan_Rbot_366f1599 {
    meta:
        author = "Elastic Security"
        id = "366f1599-a287-44e6-bc2c-d835b2c2c024"
        fingerprint = "27166c9dab20d40c10a4f0ea5d0084be63fef48748395dd55c7a13ab6468e16d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Rbot"
        reference_sample = "5553d154a0e02e7f97415299eeae78e5bb0ecfbf5454e3933d6fd9675d78b3eb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { C0 64 03 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B }
    condition:
        all of them
}

