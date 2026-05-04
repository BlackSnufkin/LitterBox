rule MacOS_Creddump_KeychainAccess_535c1511 {
    meta:
        author = "Elastic Security"
        id = "535c1511-5b45-4845-85c1-ec53f9787b96"
        fingerprint = "7c103fa75b24cdf322f6c7cf3ec56e8cc2b14666c9d9fb56a4b1a735efaf1b5b"
        creation_date = "2023-04-11"
        last_modified = "2024-08-19"
        threat_name = "Macos.Creddump.KeychainAccess"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $strings1 = "uploadkeychain" ascii wide nocase
        $strings2 = "decryptkeychain" ascii wide nocase
        $strings3 = "dump-generic-password" ascii wide nocase
        $strings4 = "keychain_extract" ascii wide nocase
        $strings5 = "chainbreaker" ascii wide nocase
        $strings6 = "SecKeychainItemCopyContent" ascii wide nocase
        $strings7 = "SecKeychainItemCopyAccess" ascii wide nocase
        $strings8 = "Failed to get password" ascii wide nocase
    condition:
        all of ($strings1, $strings2) or $strings4 or all of ($strings3, $strings5) or all of ($strings6, $strings7, $strings8)
}

