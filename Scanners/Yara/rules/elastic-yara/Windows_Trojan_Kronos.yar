rule Windows_Trojan_Kronos_cdd2e2c5 {
    meta:
        author = "Elastic Security"
        id = "cdd2e2c5-17fc-4cec-aece-0b19c54faccf"
        fingerprint = "0e124d42a6741a095b66928303731e7060788bc1035b98b729ca91e4f7b6bc44"
        creation_date = "2021-02-07"
        last_modified = "2021-08-23"
        description = "Strings used by the Kronos banking trojan and variants."
        threat_name = "Windows.Trojan.Kronos"
        reference = "https://www.virusbulletin.com/virusbulletin/2014/10/paper-evolution-webinjects"
        reference_sample = "baa9cedbbe0f5689be8f8028a6537c39e9ea8b0815ad76cb98f365ca5a41653f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "data_inject" ascii wide fullword
        $a2 = "set_filter" ascii wide fullword
        $a3 = "set_url" ascii wide fullword
        $a4 = "%ws\\%ws.cfg" ascii wide fullword
        $a5 = "D7T1H5F0F5A4C6S3" ascii wide fullword
        $a6 = "[DELETE]" ascii wide fullword
        $a7 = "Kronos" ascii wide fullword
    condition:
        4 of them
}

