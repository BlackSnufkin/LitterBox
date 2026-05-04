rule Windows_Trojan_Carberp_d6de82ae {
    meta:
        author = "Elastic Security"
        id = "d6de82ae-9846-40cb-925d-e0a371e1c44c"
        fingerprint = "7ce34f1000749a938b78508c93371d3339cd49f73eeec36b25da13c9d129b85c"
        creation_date = "2021-02-07"
        last_modified = "2021-08-23"
        description = "Identifies VNC module from the leaked Carberp source code. This could exist in other malware families."
        threat_name = "Windows.Trojan.Carberp"
        reference = "https://github.com/m0n0ph1/malware-1/blob/master/Carberp%20Botnet/source%20-%20absource/pro/all%20source/hvnc_dll/HVNC%20Lib/vnc/xvnc.h#L342"
        reference_sample = "f98fadb6feab71930bd5c08e85153898d686cc96c84fe349c00bf6d482de9b53"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = ".NET CLR Networking_Perf_Library_Lock_PID_0" ascii wide fullword
        $a2 = "FakeVNCWnd" ascii wide fullword
    condition:
        all of them
}

