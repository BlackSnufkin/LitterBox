rule Windows_Trojan_Tollbooth_85bfcc68 {
    meta:
        author = "Elastic Security"
        id = "85bfcc68-f375-4e19-817d-31ec43eac7eb"
        fingerprint = "ce6b26e974a82a180f1e924f47279a1312557f7e379da4cd2cf80c7923b4e814"
        creation_date = "2025-10-08"
        last_modified = "2025-10-13"
        threat_name = "Windows.Trojan.Tollbooth"
        reference_sample = "c1ca053e3c346513bac332b5740848ed9c496895201abc734f2de131ec1b9fb2"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "sitemapRangeBegin" ascii wide fullword
        $b = "seoGroupHijackbotUaMatchRules" ascii wide fullword
        $c = "clean?type=conf" ascii wide fullword
        $d = "/landpage?seoConfigId=" ascii wide fullword
        $e = "<!- GP -->" ascii wide fullword
        $f = "gooqlebot" ascii wide fullword
        $g = "GetRandomLinesFromMultipleResources" ascii wide fullword
        $h = "hj-plugin-iis-cpp-v"
        $i = "hj-iis-cim-v" wide
        $j = "<form action='/scjg' method='POST'"
        $k = "AffLinkServer" ascii wide
        $l = { 7B E6 9C AC E5 9C B0 E5 8F 8B E9 93 BE 7D }
        $m = { 7B 00 2C 67 30 57 CB 53 FE 94 7D 00 }
    condition:
        7 of them
}

