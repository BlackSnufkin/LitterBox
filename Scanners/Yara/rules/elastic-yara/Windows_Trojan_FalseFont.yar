rule Windows_Trojan_FalseFont_d1f0d357 {
    meta:
        author = "Elastic Security"
        id = "d1f0d357-26cb-4dab-8ca6-65f17109982b"
        fingerprint = "ad63447832e9a160d479fccd780de89b9c29b9697f69ac3553e39bc388d49b83"
        creation_date = "2024-03-26"
        last_modified = "2024-05-08"
        threat_name = "Windows.Trojan.FalseFont"
        reference_sample = "364275326bbfc4a3b89233dabdaf3230a3d149ab774678342a40644ad9f8d614"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s1 = "KillById"
        $s2 = "KillByName"
        $s3 = "SignalRHub"
        $s4 = "ExecUseShell"
        $s5 = "ExecAndKeepAlive"
        $s6 = "SendAllDirectoryWithStartPath"
        $s7 = "AppLiveDirectorySendHard"
        $s8 = "AppLiveDirectorySendScreen"
    condition:
        4 of them
}

