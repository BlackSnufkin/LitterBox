rule Linux_Trojan_Pumakit_b86138c3 {
    meta:
        author = "Elastic Security"
        id = "b86138c3-c7b3-4f86-a695-bf8195f2458c"
        fingerprint = "c5cba5975be26ebcb14871527533d1f8f082b37f2d8b509904b608569fdb8b24"
        creation_date = "2024-12-09"
        last_modified = "2024-12-11"
        threat_name = "Linux.Trojan.Pumakit"
        reference_sample = "30b26707d5fb407ef39ebee37ded7edeea2890fb5ec1ebfa09a3b3edfc80db1f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "PUMA %s"
        $str2 = "Kitsune PID %ld"
        $str3 = "/usr/share/zov_f"
        $str4 = "zarya"
        $str5 = ".puma-config"
        $str6 = "ping_interval_s"
        $str7 = "session_timeout_s"
        $str8 = "c2_timeout_s"
        $str9 = "LD_PRELOAD=/lib64/libs.so"
        $str10 = "kit_so_len"
        $str11 = "opsecurity1.art"
        $str12 = "89.23.113.204"
    condition:
        4 of them
}

