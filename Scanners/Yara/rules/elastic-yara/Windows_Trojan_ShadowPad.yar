rule Windows_Trojan_ShadowPad_be71209d {
    meta:
        author = "Elastic Security"
        id = "be71209d-b1c0-4922-87ae-47d0930d8755"
        fingerprint = "629f1502ce9f429ba6d497b8f2b0b35e57ca928a764ee6f3cb43521bfa6b5af4"
        creation_date = "2023-01-31"
        last_modified = "2023-02-01"
        description = "Target ShadowPad loader"
        threat_name = "Windows.Trojan.ShadowPad"
        reference = "https://www.elastic.co/security-labs/update-to-the-REF2924-intrusion-set-and-related-campaigns"
        reference_sample = "452b08d6d2aa673fb6ccc4af6cebdcb12b5df8722f4d70d1c3491479e7b39c05"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "{%8.8x-%4.4x-%4.4x-%8.8x%8.8x}"
    condition:
        all of them
}

rule Windows_Trojan_ShadowPad_0d899241 {
    meta:
        author = "Elastic Security"
        id = "0d899241-6ef8-4524-a728-4ed53e4d2cec"
        fingerprint = "7070eb3608c2c39804ccad4a05e4de12ec4eb47388589ef72c723b353b920a68"
        creation_date = "2023-01-31"
        last_modified = "2023-02-01"
        description = "Target ShadowPad payload"
        threat_name = "Windows.Trojan.ShadowPad"
        reference = "https://www.elastic.co/security-labs/update-to-the-REF2924-intrusion-set-and-related-campaigns"
        reference_sample = "cb3a425565b854f7b892e6ebfb3734c92418c83cd590fc1ee9506bcf4d8e02ea"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "hH#whH#w" fullword
        $a2 = "Yuv~YuvsYuvhYuv]YuvRYuvGYuv1:tv<Yuvb#tv1Yuv-8tv&Yuv" fullword
        $a3 = "pH#wpH#w" fullword
        $a4 = "HH#wHH#wA" fullword
        $a5 = "xH#wxH#w:$" fullword
        $re1 = /(HTTPS|TCP|UDP):\/\/[^:]+:443/
    condition:
        4 of them
}

