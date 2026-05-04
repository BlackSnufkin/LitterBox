rule Windows_Ransomware_Hellokitty_8859e8e8 {
    meta:
        author = "Elastic Security"
        id = "8859e8e8-f94c-4853-b296-1fc801486c57"
        fingerprint = "f9791409d2a058dd68dc09df5e4b597c6c6a1f0da9801d7ab9e678577b621730"
        creation_date = "2021-05-03"
        last_modified = "2021-08-23"
        threat_name = "Windows.Ransomware.Hellokitty"
        reference_sample = "3ae7bedf236d4e53a33f3a3e1e80eae2d93e91b1988da2f7fcb8fde5dcc3a0e9"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "HelloKittyMutex" wide fullword
        $a2 = "%s\\read_me_lkd.txt" wide fullword
        $a3 = "Win32_ShadowCopy.ID='%s'" wide fullword
        $a4 = "Trying to decrypt or modify the files with programs other than our decryptor can lead to permanent loss of data!" wide fullword
        $a5 = "%s/secret/%S" wide fullword
        $a6 = "DECRYPT_NOTE.txt" wide fullword
        $a7 = "Some data has been stored in our servers and ready for publish." wide fullword
        $a9 = "To contact with us you have ONE week from the encryption time, after decryption keys and your personal contact link will be dele" wide
        $a10 = "In case of your disregard, we reserve the right to dispose of the dumped data at our discretion including publishing." wide fullword
        $a11 = "IMPORTANT: Don't modify encrypted files or you can damage them and decryption will be impossible!" wide fullword
        $b1 = "/f /im \"%s\"" wide fullword
        $b2 = "stop \"%s\"" wide fullword
        $b3 = "/f /im %s" wide fullword
        $b4 = "stop %s" wide fullword
    condition:
        (2 of ($a*) and 2 of ($b*)) or (5 of ($a*))
}

rule Windows_Ransomware_Hellokitty_4b668121 {
    meta:
        author = "Elastic Security"
        id = "4b668121-cc21-4f0b-b0fc-c2b5b4cb53e8"
        fingerprint = "834316ce0f3225b1654b3c4bccb673c9ad815e422276f61e929d5440ca51a9fa"
        creation_date = "2021-05-03"
        last_modified = "2021-08-23"
        threat_name = "Windows.Ransomware.Hellokitty"
        reference_sample = "9a7daafc56300bd94ceef23eac56a0735b63ec6b9a7a409fb5a9b63efe1aa0b0"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "(%d) [%d] %s: STOP DOUBLE PROCESS RUN" ascii fullword
        $a2 = "(%d) [%d] %s: Looking for folder from cmd: %S" ascii fullword
        $a3 = "(%d) [%d] %s: ERROR: Failed to encrypt AES block" ascii fullword
        $a4 = "gHelloKittyMutex" wide fullword
        $a5 = "/C ping 127.0.0.1 & del %s" wide fullword
        $a6 = "Trying to decrypt or modify the files with programs other than our decryptor can lead to permanent loss of data!"
        $a7 = "read_me_lkdtt.txt" wide fullword
        $a8 = "If you want to get it, you must pay us some money and we will help you." wide fullword
    condition:
        5 of them
}

rule Windows_Ransomware_Hellokitty_d9391a1a {
    meta:
        author = "Elastic Security"
        id = "d9391a1a-78d3-4ae6-8e45-630ceec8bade"
        fingerprint = "8779a926a237af0a966534931b60acd54f5d6d65063c070a3621ec604e280ff8"
        creation_date = "2021-05-03"
        last_modified = "2023-01-04"
        threat_name = "Windows.Ransomware.Hellokitty"
        reference_sample = "10887d13dba1f83ef34e047455a04416d25a83079a7f3798ce3483e0526e3768"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 83 C4 04 85 DB 75 12 0F 10 45 D4 83 C7 10 0F 11 06 83 C6 10 83 }
        $a2 = { 89 45 F8 3B 5D F4 75 25 3B C6 75 21 6A FF FF 75 14 8B D1 83 }
    condition:
        any of them
}

