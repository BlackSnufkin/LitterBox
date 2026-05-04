rule Windows_Ransomware_Medusa_fda487fd {
    meta:
        author = "Elastic Security"
        id = "fda487fd-2888-41a3-99de-dbeba6723b4c"
        fingerprint = "3d734cf169fe60a7d04dfe4631287bc3b5ec790d1e2c91d022dc31a68697c5ef"
        creation_date = "2025-02-04"
        last_modified = "2025-02-11"
        threat_name = "Windows.Ransomware.Medusa"
        reference_sample = "3a6d5694eec724726efa3327a50fad3efdc623c08d647b51e51cd578bddda3da"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "kill_processes %s" ascii fullword
        $a2 = "kill_services %s" ascii fullword
        $a3 = ":note path = %s" ascii fullword
        $a4 = "Write Note file error:%s" ascii fullword
        $a5 = "Rename file error:%s" ascii fullword
        $a6 = "G:\\Medusa\\Release\\gaze.pdb" ascii fullword
    condition:
        5 of them
}

