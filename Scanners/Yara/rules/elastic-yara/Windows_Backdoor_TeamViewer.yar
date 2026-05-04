rule Windows_Backdoor_TeamViewer_df8e7326 {
    meta:
        author = "Elastic Security"
        id = "df8e7326-5879-48d7-8a5f-1c9a2d8b7f8d"
        fingerprint = "0f2406e98fa1383e39672bd4ec32a111363f7d33f8bc33c2bd7ea36353faab45"
        creation_date = "2022-10-29"
        last_modified = "2022-12-20"
        threat_name = "Windows.Backdoor.TeamViewer"
        reference = "https://vms.drweb.com/virus/?i=8172096"
        reference_sample = "68d9ffb6e00c2694d0d827108d0410d5a66d4f8cf839afddd17c5887b0149350"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "m%c%c%c%c%c%c.com" ascii fullword
        $a2 = "client_id=%.8x&connected=%d&server_port=%d&debug=%d&os=%d.%d.%04d&dgt=%d&dti=%d" ascii fullword
        $a3 = "\\save.dat" ascii fullword
        $a4 = "auth_ip" ascii fullword
        $a5 = "updips" ascii fullword
        $b1 = { 55 8B EC 56 E8 BF 25 00 00 50 E8 7B 5B 00 00 8B F0 59 85 F6 75 2C 8B 75 08 56 E8 A9 25 00 00 50 }
    condition:
        5 of ($a*) or 1 of ($b*)
}

