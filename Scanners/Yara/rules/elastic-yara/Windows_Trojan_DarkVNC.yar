rule Windows_Trojan_DarkVNC_bd803c2e {
    meta:
        author = "Elastic Security"
        id = "bd803c2e-77bd-4b8c-bdfa-11a9bd54a454"
        fingerprint = "131f4b3ef5b01720a52958058ecc4c3681ed0ca975a1a06cd034d7205680e710"
        creation_date = "2023-01-23"
        last_modified = "2023-02-01"
        threat_name = "Windows.Trojan.DarkVNC"
        reference_sample = "0fcc1b02fdaf211c772bd4fa1abcdeb5338d95911c226a9250200ff7f8e45601"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "BOT-%s(%s)_%S-%S%u%u" wide fullword
        $a2 = "{%08X-%04X-%04X-%04X-%08X%04X}" wide fullword
        $a3 = "monitor_off / monitor_on" ascii fullword
        $a4 = "bot_shell >" ascii fullword
        $a5 = "keyboard and mouse are blocked !" ascii fullword
    condition:
        all of them
}

