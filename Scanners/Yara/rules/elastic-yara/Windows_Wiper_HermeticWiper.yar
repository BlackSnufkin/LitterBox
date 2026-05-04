rule Windows_Wiper_HermeticWiper_7206a969 {
    meta:
        author = "Elastic Security"
        id = "7206a969-bbd6-4c2d-a19d-380b71a4ab08"
        fingerprint = "e3486c785f99f4376d4161704afcaf61e8a5ab6101463a76d134469f8a5581bf"
        creation_date = "2022-02-24"
        last_modified = "2022-02-24"
        threat_name = "Windows.Wiper.HermeticWiper"
        reference = "https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper"
        reference_sample = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "\\\\?\\C:\\Windows\\System32\\winevt\\Logs" wide fullword
        $a2 = "\\\\.\\EPMNTDRV\\%u" wide fullword
        $a3 = "tdrv.pdb" ascii fullword
        $a4 = "%s%.2s" wide fullword
        $a5 = "ccessdri" ascii fullword
        $a6 = "Hermetica Digital"
    condition:
        all of them
}

