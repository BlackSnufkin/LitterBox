rule Windows_Trojan_Pony_d5516fe8 {
    meta:
        author = "Elastic Security"
        id = "d5516fe8-3b25-4c46-9e5b-111ca312a824"
        fingerprint = "9d4d847f55a693a45179a904efe20afd05a92650ac47fb19ef523d469a33795f"
        creation_date = "2021-08-14"
        last_modified = "2021-10-04"
        threat_name = "Windows.Trojan.Pony"
        reference_sample = "423e792fcd00265960877482e8148a0d49f0898f4bbc190894721fde22638567"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "\\Global Downloader" ascii fullword
        $a2 = "wiseftpsrvs.bin" ascii fullword
        $a3 = "SiteServer %d\\SFTP" ascii fullword
        $a4 = "%s\\Keychain" ascii fullword
        $a5 = "Connections.txt" ascii fullword
        $a6 = "ftpshell.fsi" ascii fullword
        $a7 = "inetcomm server passwords" ascii fullword
    condition:
        all of them
}

