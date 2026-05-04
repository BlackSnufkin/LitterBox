rule Windows_Trojan_A310logger_520cd7ec {
    meta:
        author = "Elastic Security"
        id = "520cd7ec-840c-4d45-961b-8bc5e329c52f"
        fingerprint = "f4ee88e555b7bd0102403cc804372f5376debc59555e8e7b4a16e18b04d1b314"
        creation_date = "2022-01-11"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.A310logger"
        reference_sample = "60fb9597e5843c72d761525f73ca728409579d81901860981ebd84f7d153cfa3"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "/dumps9taw" ascii fullword
        $a2 = "/logstatus" ascii fullword
        $a3 = "/checkprotection" ascii fullword
        $a4 = "[CLIPBOARD]<<" wide fullword
        $a5 = "&chat_id=" wide fullword
    condition:
        all of them
}

