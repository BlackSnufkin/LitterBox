rule Windows_Trojan_Hancitor_6738d84a {
    meta:
        author = "Elastic Security"
        id = "6738d84a-7393-4db2-97cc-66f471b5699a"
        fingerprint = "44a4dd7c35e0b4f3f161b82463d8f0ee113eaedbfabb7d914ce9486b6bd3a912"
        creation_date = "2021-06-17"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Hancitor"
        reference_sample = "a674898f39377e538f9ec54197689c6fa15f00f51aa0b5cc75c2bafd86384a40"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d"
        $b1 = "Rundll32.exe %s, start" ascii fullword
        $b2 = "MASSLoader.dll" ascii fullword
    condition:
        $a1 or all of ($b*)
}

