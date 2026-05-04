rule Windows_Trojan_BadIIS_2a604c44 {
    meta:
        author = "Elastic Security"
        id = "2a604c44-80ad-4b25-abdc-6f57074a3b37"
        fingerprint = "3568b0878dd8404aa5a99101c132b158cea015a5397a114a28fc2057258a6f24"
        creation_date = "2026-01-26"
        last_modified = "2026-02-02"
        threat_name = "Windows.Trojan.BadIIS"
        reference_sample = "1b723a5f9725b607926e925d1797f7ec9664bb308c9602002345485e18085b72"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 FF C0 80 3C 01 00 75 F7 48 8B 72 08 }
        $a2 = { 0F 11 45 D8 4C 89 75 E8 4C 89 75 F0 4D 8B EE 4C 89 75 E8 41 BC }
        $a3 = { 49 8B C7 48 C1 E8 04 4C 8D 25 [2] 02 00 46 0F B6 }
        $a5 = { 48 8B 45 C7 48 83 F8 01 72 29 48 FF }
        $a6 = { 0F B6 44 37 FF 48 2B F8 }
    condition:
        3 of them
}

rule Windows_Trojan_BadIIS_56117744 {
    meta:
        author = "Elastic Security"
        id = "56117744-f09a-4efa-bfc6-0f2273e6025c"
        fingerprint = "d83da4a12e47bf898a4150b2c2c4c2815f9bcf59e48ea7cd416ff2a8382580ba"
        creation_date = "2026-01-26"
        last_modified = "2026-02-02"
        threat_name = "Windows.Trojan.BadIIS"
        reference_sample = "a69a5fe19eae825c463e83265f7bbe31d1e514176e11ba5f63c25351542c46b6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "bing|google|naver" fullword
        $a2 = "bingbot|Googlebot|Yeti" fullword
        $a3 = "bingbot|Googlebot|coccocbot" fullword
        $a4 = "|split'.split('|'),0,{}))</script>\n" fullword
        $a5 = "iPhone|iPad|iPod|iOS|Android|uc|BlackBerry|HUAWEI" fullword
        $a6 = ".js|.css|.jpg|.jpeg|.png|.gif|.bmp|.ico|.svg|.tif|.pict|.tiff|.swf" fullword
        $a7 = "tee|pat|and|app|poker|gam|sto|vid|bea|slo|fis|bac|pac|tig|bmw|fru|bull|card|gods|fish|mahj" fullword
        $a8 = "return||if|replace|while||13|eval|toString|String||new||RegExp|script|window|document||write|type|text|javascript|src" fullword
    condition:
        4 of them
}

rule Windows_Trojan_BadIIS_71069efd {
    meta:
        author = "Elastic Security"
        id = "71069efd-75a4-4752-8b31-a8ac0a17cfc0"
        fingerprint = "e775c597c743e41dd11e4aedce991609d81764fd3b31ed29efcea1cc57fce81f"
        creation_date = "2026-01-26"
        last_modified = "2026-02-02"
        threat_name = "Windows.Trojan.BadIIS"
        reference_sample = "c5abe6936fe111bbded1757a90c934a9e18d849edd70e56a451c1547688ff96f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "hm.baidu.com/hm.js" fullword
        $a2 = "googletagmanager.com/gtag/js?id" fullword
        $a3 = "</div>\n<a id=\"js-alert-btn\" class=\"alert-btn\" href=\"" fullword
        $a4 = "index.php?domain=" fullword
        $seq1 = { C7 45 C4 [4] C7 45 C8 04 00 00 00 C7 45 CC [4] C7 45 D0 04 00 00 00 }
        $seq2 = { C7 45 E8 07 00 00 00 C7 45 EC [4] C7 45 F0 04 00 00 00 C7 45 F4 [4] C7 45 F8 09 00 00 00 }
    condition:
        2 of ($a*) and 1 of ($seq*)
}

