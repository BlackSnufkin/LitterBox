rule Windows_Trojan_MagicRat_c14c4d85 {
    meta:
        author = "Elastic Security"
        id = "c14c4d85-27d7-46a6-a520-55de7a3a8c16"
        fingerprint = "320dcd7e644445a32b95b34632ab5dc7b64b9f71cc6ec36618d71a391f71c960"
        creation_date = "2024-12-27"
        last_modified = "2025-02-11"
        threat_name = "Windows.Trojan.MagicRat"
        reference_sample = "9dc04153455d054d7e04d46bcd8c13dd1ca16ab2995e518ba9bf33b43008d592"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str_0 = "MagicSystem" fullword
        $str_1 = "MagicMon" fullword
        $str_2 = "company/oracle" fullword
        $str_3 = "company/microsoft" fullword
        $str_4 = "images/body/" fullword
        $str_5 = "&filename=" fullword
        $str_6 = "os/mac" fullword
        $str_7 = "form-data; name=\"session\";" fullword
    condition:
        5 of them
}

