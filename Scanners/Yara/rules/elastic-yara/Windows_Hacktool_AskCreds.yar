rule Windows_Hacktool_AskCreds_34e3e3d4 {
    meta:
        author = "Elastic Security"
        id = "34e3e3d4-7516-4e0e-b3e7-5bc84404bd08"
        fingerprint = "e00dd2496045d1b71119b35c30c4c010c0ad57f67691649c0f4d206f837bd05d"
        creation_date = "2023-05-16"
        last_modified = "2023-06-13"
        threat_name = "Windows.Hacktool.AskCreds"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Failed to create AskCreds thread."
        $a2 = "CredUIPromptForWindowsCredentialsW failed"
        $a3 = "[+] Password: %ls"
    condition:
        2 of them
}

