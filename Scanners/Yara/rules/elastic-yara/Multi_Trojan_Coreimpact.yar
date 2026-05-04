rule Multi_Trojan_Coreimpact_37703dc3 {
    meta:
        author = "Elastic Security"
        id = "37703dc3-9485-4026-a8b7-82e753993757"
        fingerprint = "5a4d7af7d0fecc05f87ba51f976d78e77622f8afb1eafc175444f45839490109"
        creation_date = "2022-08-10"
        last_modified = "2022-09-29"
        threat_name = "Multi.Trojan.Coreimpact"
        reference_sample = "2d954908da9f63cd3942c0df2e8bb5fe861ac5a336ddef2bd0a977cebe030ad7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $str1 = "Uh, oh, exit() failed" fullword
        $str2 = "agent_recv" fullword
        $str3 = "needroot" fullword
        $str4 = "time is running backwards, corrected" fullword
        $str5 = "junk pointer, too low to make sense" fullword
    condition:
        3 of them
}

