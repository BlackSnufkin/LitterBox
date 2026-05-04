rule Windows_Trojan_StormKitty_6256031a {
    meta:
        author = "Elastic Security"
        id = "6256031a-e7dd-423b-a83f-4db428cb3d1b"
        fingerprint = "6f0463de42c97701b0f3b8172e7e461501357921a3d11e6ca467bd1ca397d0b6"
        creation_date = "2022-03-21"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.StormKitty"
        reference_sample = "0c69015f534d1da3770dbc14183474a643c4332de6a599278832abd2b15ba027"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "https://github.com/LimerBoy/StormKitty" ascii fullword
        $a2 = "127.0.0.1 www.malwarebytes.com" wide fullword
        $a3 = "KillDefender"
        $a4 = "Username: {1}" wide fullword
        $a5 = "# End of Cookies" wide fullword
        $a6 = "# End of Passwords" wide fullword
    condition:
        all of them
}

