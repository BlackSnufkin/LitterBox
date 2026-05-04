rule Linux_Trojan_Skidmap_aa7b661d {
    meta:
        author = "Elastic Security"
        id = "aa7b661d-0ecc-4171-a0c2-a6c0c91b6d27"
        fingerprint = "0bd6bec14d4b0205b04c6b4f34988ad95161f954a1f0319dd33513cb2c7e5f59"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Skidmap"
        reference_sample = "4282ba9b7bee69d42bfff129fff45494fb8f7db0e1897fc5aa1e4265cb6831d9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { E8 41 41 80 F8 1A 41 0F 43 C1 88 04 0E 48 83 C1 01 0F B6 04 0F }
    condition:
        all of them
}

rule Linux_Trojan_Skidmap_52fb8489 {
    meta:
        author = "Elastic Security"
        id = "52fb8489-4877-4543-8d7a-03f7cad50b0a"
        fingerprint = "44ba77d99648660bd1091cb47fad42422a5cd26b9df848f1f9febdfd4d764540"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Trojan.Skidmap"
        reference_sample = "4282ba9b7bee69d42bfff129fff45494fb8f7db0e1897fc5aa1e4265cb6831d9"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $func1 = "hideModule"
        $func2 = "hook_local_out_func"
        $func3 = "hook_local_in_func"
        $func4 = "orig_getdents"
        $func5 = "hacked_getdents"
        $hook1 = "fake_seq_show_ipv4_udp"
        $hook2 = "fake_seq_show_ipv6_tcp"
        $hook3 = "fake_seq_show_ipv6_udp"
        $hook4 = "fake_seq_show_ipv4_tcp"
        $hook5 = "fake_account_user_time"
        $hook6 = "fake_loadavg_proc_show"
        $hook7 = "fake_trace_printk"
        $hook8 = "fake_bpf_trace_printk"
        $hook9 = "fake_crash_kexec"
        $hook10 = "fake_sched_debug_show"
        $str1 = "pamdicks"
        $str2 = "netlink"
        $str3 = "kaudited"
        $str4 = "kswaped"
    condition:
        3 of ($func*) or 4 of ($hook*) or 3 of ($str*)
}

