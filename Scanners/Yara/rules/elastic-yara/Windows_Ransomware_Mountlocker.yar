rule Windows_Ransomware_Mountlocker_126a76e2 {
    meta:
        author = "Elastic Security"
        id = "126a76e2-8a97-4347-ac36-9437a512e16c"
        fingerprint = "08213f4474c7c8fd7a6e59c9ff139fb45f224109ad4e6162c12cff5ac85cb10c"
        creation_date = "2021-06-10"
        last_modified = "2021-08-23"
        threat_name = "Windows.Ransomware.Mountlocker"
        reference_sample = "4a5ac3c6f8383cc33c795804ba5f7f5553c029bbb4a6d28f1e4d8fb5107902c1"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "[SKIP] locker.dir.check > black_list name=%s" wide fullword
        $a2 = "[OK] locker.dir.check > name=%s" wide fullword
        $a3 = "[ERROR] locker.worm > execute pcname=%s" wide fullword
        $a4 = "[INFO] locker.work.enum.net_drive > enum finish name=%s" wide fullword
        $a5 = "[WARN] locker.work.enum.server_shares > logon on server error=%u pcname=%s" wide fullword
    condition:
        any of them
}

