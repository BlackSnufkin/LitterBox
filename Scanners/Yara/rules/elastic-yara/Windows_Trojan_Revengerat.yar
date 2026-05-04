rule Windows_Trojan_Revengerat_db91bcc6 {
    meta:
        author = "Elastic Security"
        id = "db91bcc6-024d-42da-8d0a-bd69374bf622"
        fingerprint = "9c322655f50c32b9be23accd2b38fbda43c280284fbf05a5a5c98458c2bab666"
        creation_date = "2021-09-02"
        last_modified = "2022-01-13"
        threat_name = "Windows.Trojan.Revengerat"
        reference_sample = "30d8f81a19976d67b495eb1324372598cc25e1e69179c11efa22025341e455bd"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Revenge-RAT" wide fullword
        $a2 = "SELECT * FROM FirewallProduct" wide fullword
        $a3 = "HKEY_CURRENT_USER\\SOFTWARE\\" wide fullword
        $a4 = "get_MachineName" ascii fullword
    condition:
        all of them
}

