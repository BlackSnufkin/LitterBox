rule Windows_Ransomware_Mespinoza_3adb59f5 {
    meta:
        author = "Elastic Security"
        id = "3adb59f5-a4af-48f2-8029-874a62b23651"
        fingerprint = "f44a79048427e79d339d3b0ccaeb85ba6731d5548256a2615f32970dcf67578f"
        creation_date = "2021-08-05"
        last_modified = "2021-10-04"
        threat_name = "Windows.Ransomware.Mespinoza"
        reference_sample = "6f3cd5f05ab4f404c78bab92f705c91d967b31a9b06017d910af312fa87ae3d6"
        severity = 90
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Don't try to use backups because it were encrypted too." ascii fullword
        $a2 = "Every byte on any types of your devices was encrypted." ascii fullword
        $a3 = "n.pysa" wide fullword
    condition:
        all of them
}

