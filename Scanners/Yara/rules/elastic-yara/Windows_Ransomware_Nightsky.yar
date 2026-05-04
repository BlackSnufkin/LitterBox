rule Windows_Ransomware_Nightsky_a7f19411 {
    meta:
        author = "Elastic Security"
        id = "a7f19411-4c28-4cc7-b60c-ef51cb10b905"
        fingerprint = "0f2aac3a538a921b78f7c2521adf65678830abab8ec8b360ac3dddae5fbc4756"
        creation_date = "2022-01-11"
        last_modified = "2022-04-12"
        threat_name = "Windows.Ransomware.Nightsky"
        reference_sample = "1fca1cd04992e0fcaa714d9dfa97323d81d7e3d43a024ec37d1c7a2767a17577"
        severity = 90
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "\\NightSkyReadMe.hta" wide fullword
        $a2 = ".nightsky" wide fullword
        $a3 = "<h1 id=\"nightsky\"><center><span style=\"color: black; font-size: 48pt\">NIGHT SKY</span></center>" ascii fullword
        $a4 = "URL:https://contact.nightsky.cyou" ascii fullword
    condition:
        2 of them
}

rule Windows_Ransomware_Nightsky_253c4d0d {
    meta:
        author = "Elastic Security"
        id = "253c4d0d-157f-4929-9f0e-5830ebc377dc"
        fingerprint = "739529dfb1f8c8ab2a7f6a4b2b18b27dd2fcc38eda0f110897fc6cb5d64b1c92"
        creation_date = "2022-03-14"
        last_modified = "2022-04-12"
        threat_name = "Windows.Ransomware.Nightsky"
        reference_sample = "2c940a35025dd3847f7c954a282f65e9c2312d2ada28686f9d1dc73d1c500224"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 43 B8 48 2B D9 49 89 43 C0 4C 8B E2 49 89 43 C8 4C 8B F1 49 89 }
    condition:
        all of them
}

