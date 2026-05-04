rule Linux_Hacktool_Lightning_d9a9173a {
    meta:
        author = "Elastic Security"
        id = "d9a9173a-6372-4892-8913-77f5749aa045"
        fingerprint = "f6e9d662f22b6f08c5e6d32994d6ed933c6863870352dfb76e1540676663e7e0"
        creation_date = "2022-11-08"
        last_modified = "2024-02-13"
        threat_name = "Linux.Hacktool.Lightning"
        reference = "https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/"
        reference_sample = "48f9471c20316b295704e6f8feb2196dd619799edec5835734fc24051f45c5b7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "cat /sys/class/net/%s/address" ascii fullword
        $a2 = "{\"ComputerName\":\"%s\",\"Guid\":\"%s\",\"RequestName\":\"%s\",\"Licence\":\"%s\"}" ascii fullword
        $a3 = "sleep 60 && ./%s &" ascii fullword
        $a4 = "Lightning.Core" ascii fullword
    condition:
        all of them
}

rule Linux_Hacktool_Lightning_e87c9d50 {
    meta:
        author = "Elastic Security"
        id = "e87c9d50-dafc-45bd-8786-5df646108c8a"
        fingerprint = "22b982866241d50b6e5d964ee190f6d07982a5d3f0b2352d863c20432d5f785e"
        creation_date = "2022-11-08"
        last_modified = "2024-02-13"
        threat_name = "Linux.Hacktool.Lightning"
        reference = "https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/"
        reference_sample = "fd285c2fb4d42dde23590118dba016bf5b846625da3abdbe48773530a07bcd1e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "Execute %s Faild." ascii fullword
        $a2 = "Lightning.Downloader" ascii fullword
        $a3 = "Execute %s Success." ascii fullword
        $a4 = "[-] Socks5 are Running!" ascii fullword
        $a5 = "[-] Get FileInfo(%s) Faild!" ascii fullword
    condition:
        all of them
}

rule Linux_Hacktool_Lightning_3bcac358 {
    meta:
        author = "Elastic Security"
        id = "3bcac358-b4b9-43ae-b173-bebe0c9ff899"
        fingerprint = "7108fab0ed64416cf16134475972f99c24aaaf8a4165b83287f9bdbf5050933b"
        creation_date = "2022-11-08"
        last_modified = "2024-02-13"
        threat_name = "Linux.Hacktool.Lightning"
        reference = "https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/"
        reference_sample = "ad16989a3ebf0b416681f8db31af098e02eabd25452f8d781383547ead395237"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "[+] %s:%s %d,ntop:%s,strport:%s" ascii fullword
        $a2 = "%s: reading file \"%s\"" ascii fullword
        $a3 = "%s: kill(%d): %s" ascii fullword
        $a4 = "%s exec \"%s\": %s" ascii fullword
    condition:
        all of them
}

