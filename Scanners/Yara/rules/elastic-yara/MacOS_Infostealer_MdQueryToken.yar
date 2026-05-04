rule MacOS_Infostealer_MdQueryToken_1c52d574 {
    meta:
        author = "Elastic Security"
        id = "1c52d574-4fb7-4f14-b100-291e3f296c94"
        fingerprint = "f603e5383d08050cd84949fb60ce5618c4dfff54bcb3f035290adc1c1cc0e0e1"
        creation_date = "2023-04-11"
        last_modified = "2024-08-19"
        threat_name = "MacOS.Infostealer.MdQueryToken"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $string1 = /kMDItemTextContent\s{1,50}==\s{1,50}\S{1,50}token/ ascii wide nocase
        $string2 = /kMDItemDisplayName\s{1,50}==\s{1,50}\S{1,50}token\S{1,50}/ ascii wide nocase
    condition:
        any of ($string1, $string2)
}

