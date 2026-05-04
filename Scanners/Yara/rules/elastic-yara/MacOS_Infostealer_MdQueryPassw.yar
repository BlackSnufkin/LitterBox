rule MacOS_Infostealer_MdQueryPassw_6125f987 {
    meta:
        author = "Elastic Security"
        id = "6125f987-b5a4-4999-ab39-ff312a43f6d9"
        fingerprint = "744e5e82bd90dc75031c2ce8208e9b8d10f062a57666f7e7be9428321f2929cc"
        creation_date = "2023-04-11"
        last_modified = "2024-08-19"
        threat_name = "MacOS.Infostealer.MdQueryPassw"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $string1 = /kMDItemTextContent\s{1,50}==\s{1,50}\S{1,50}passw/ ascii wide nocase
        $string2 = /kMDItemDisplayName\s{1,50}==\s{1,50}\S{1,50}passw\S{1,50}/ ascii wide nocase
    condition:
        any of ($string1, $string2)
}

