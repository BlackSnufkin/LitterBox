rule Windows_Ransomware_Vgod_86a877fd {
    meta:
        author = "Elastic Security"
        id = "86a877fd-d140-4df4-bdfc-d9716ef6f94a"
        fingerprint = "70d8ecc6e2cf8a895672c11851c78eea635303190bd0db71fa9ed481b3f56cf2"
        creation_date = "2025-02-18"
        last_modified = "2025-05-27"
        threat_name = "Windows.Ransomware.Vgod"
        reference_sample = "241c3b02a8e7d5a2b9c99574c28200df2a0f8c8bd7ba4d262e6aa8ed1211ba1f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Vgod-Ransomware/configuration.init" fullword
        $a2 = "Vgod-Ransomware/encryption.EncryptFile" fullword
        $a3 = "/Vgod-Ransomware/Vgod-Ransomware/Encryptor/encryption/encryption.go" fullword
        $a4 = "main.removeBuiltExe" fullword
        $a5 = "Contact Mail: vgod@ro.ru" fullword
        $a6 = "Vgod-Built.exe" fullword
        $a7 = "indicate your ID and if you want attach 2-3 infected files to generate a private key and compile the decryptor" fullword
        $a8 = "--------- Attention ---------\nDo not rename encrypted files." fullword
    condition:
        3 of them
}

