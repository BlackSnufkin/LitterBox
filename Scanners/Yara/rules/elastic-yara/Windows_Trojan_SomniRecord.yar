rule Windows_Trojan_SomniRecord_097e66bd {
    meta:
        author = "Elastic Security"
        id = "097e66bd-5ce3-4f05-92f3-ed03719dc60a"
        fingerprint = "db4896c85b5a8aa75a4ca3f6944041a4548b6998880c689cb7a318023893ff04"
        creation_date = "2023-03-01"
        last_modified = "2023-03-20"
        threat_name = "Windows.Trojan.SomniRecord"
        reference = "https://www.elastic.co/security-labs/not-sleeping-anymore-somnirecords-wakeup-call"
        reference_sample = "54114c23f499738a06fd8b8ab2a8458c03ac8cc81e706702fcd1c64a075e4dcc"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 66 81 38 4E 52 75 06 80 78 02 3A 74 34 48 FF C0 4C 8D 47 FE 4C 2B C0 48 8B C8 BA 4E 00 00 00 }
        $str0 = "%s-%s-%s.%s" ascii fullword
        $str1 = "ECM-" ascii fullword
        $str2 = "RESP:" ascii fullword
        $str3 = "PROBE" ascii fullword
        $str4 = "SYS" ascii fullword
        $str5 = "PSL" ascii fullword
        $str6 = "WS-" ascii fullword
        $str7 = "There were no commands" ascii fullword
        $str8 = "String abc = Request.Form" ascii fullword
    condition:
        $a or all of ($str*)
}

