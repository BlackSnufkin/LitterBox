rule Linux_Rootkit_Generic_61229bdf {
    meta:
        author = "Elastic Security"
        id = "61229bdf-0b78-48b1-8a4d-09836dd2bcac"
        fingerprint = "8180ee7a04fd5ba23700e77ad3be7f30d592e77cffa8ebee8de7094627446335"
        creation_date = "2024-11-14"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "dropshell"
        $str2 = "fake_account_user_time"
        $str3 = "fake_bpf_trace_printk"
        $str4 = "fake_crash_kexec"
        $str5 = "fake_loadavg_proc_show"
        $str6 = "fake_sched_debug_show"
        $str7 = "fake_seq_show_ipv4_tcp"
        $str8 = "fake_seq_show_ipv4_udp"
        $str9 = "fake_seq_show_ipv6_tcp"
        $str10 = "fake_seq_show_ipv6_udp"
        $str11 = "fake_trace_printk"
        $str12 = "give_root"
        $str13 = "hack_getdents"
        $str14 = "hacked_getdents64"
        $str15 = "hacked_kill"
        $str16 = "hideModule"
        $str17 = "hide_module"
        $str18 = "hide_tcp4_port"
        $str19 = "hide_tcp6_port"
        $str20 = "hidden_tcp4_ports"
        $str21 = "hidden_tcp6_ports"
        $str22 = "hidden_udp4_ports"
        $str23 = "hidden_udp6_ports"
        $str24 = "hook_getdents"
        $str25 = "hook_kill"
        $str26 = "hook_local_in_func"
        $str27 = "hook_local_out_func"
        $str28 = "hook_tcp4_seq_show"
        $str29 = "hook_tcp6_seq_show"
        $str30 = "hooked_tcp6_seq_show"
        $str31 = "hooked_udp4_seq_show"
        $str32 = "hooked_udp6_seq_show"
        $str33 = "is_invisible"
        $str34 = "module_hide"
        $str35 = "module_show"
        $str36 = "nf_inet_hooks"
        $str37 = "old_access"
        $str38 = "old_fopen"
        $str39 = "old_lxstat"
        $str40 = "old_open"
        $str41 = "old_opendir"
        $str42 = "old_readdir"
        $str43 = "old_rmdir"
        $str44 = "old_unlink"
        $str45 = "old_xstat"
        $str46 = "orig_getdents"
        $str47 = "orig_getdents64"
        $str48 = "orig_kill"
        $str49 = "orig_tcp4_seq_show"
        $str50 = "orig_tcp6_seq_show"
        $str51 = "secret_connection"
        $str52 = "unhide_file"
        $str53 = "unhide_proc"
        $str54 = "unhide_tcp4_port"
        $str55 = "unhide_tcp6_port"
        $str56 = "unhide_udp4_port"
        $str57 = "unhide_udp6_port"
    condition:
        4 of ($str*)
}

rule Linux_Rootkit_Generic_482bca48 {
    meta:
        author = "Elastic Security"
        id = "482bca48-c337-45d9-9513-301909cbda73"
        fingerprint = "a2a005777e1bc236a30f3efff8d85af360665bd9418b77aa8d0aaf72a72df88a"
        creation_date = "2024-11-14"
        last_modified = "2024-12-09"
        threat_name = "Linux.Rootkit.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "sys_call_table"
        $str2 = "kallsyms_lookup_name"
        $str3 = "retpoline=Y"
        $str4 = "kprobe"
        $rk1 = "rootkit"
        $rk2 = "hide_"
        $rk3 = "hacked_"
        $rk4 = "fake_"
        $rk5 = "hooked_"
        $hook1 = "_getdents"
        $hook2 = "_kill"
        $hook3 = "_seq_show_ipv4_tcp"
        $hook4 = "_seq_show_ipv4_udp"
        $hook5 = "_seq_show_ipv6_tcp"
        $hook6 = "_seq_show_ipv6_udp"
        $hook7 = "_tcp4_port"
        $hook8 = "_tcp4_seq_show"
        $hook9 = "_tcp6_port"
        $hook10 = "_tcp6_seq_show"
        $hook11 = "_udp4_port"
        $hook12 = "_udp4_seq_show"
        $hook13 = "_udp6_port"
        $hook14 = "_udp6_seq_show"
        $hook15 = "_unlink"
    condition:
        3 of ($str*) and ((all of ($rk*)) or (3 of ($rk*) and 5 of ($hook*)))
}

rule Linux_Rootkit_Generic_d0c5cfe0 {
    meta:
        author = "Elastic Security"
        id = "d0c5cfe0-850b-432c-924d-547252ca0dd0"
        fingerprint = "6c005d7126485220c8ea1a7fb2a3215ade16f1b9dda7b89daf7a8cc408288efa"
        creation_date = "2024-11-14"
        last_modified = "2024-12-09"
        threat_name = "Linux.Rootkit.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "sys_call_table"
        $str2 = "kallsyms_lookup_name"
        $str3 = "retpoline=Y"
        $str4 = "kprobe"
        $init1 = "init_module"
        $init2 = "finit_module"
        $hook1 = "getdents"
        $hook2 = "seq_show_ipv4_tcp"
        $hook3 = "seq_show_ipv4_udp"
        $hook4 = "seq_show_ipv6_tcp"
        $hook5 = "seq_show_ipv6_udp"
        $hook6 = "sys_kill"
        $hook7 = "tcp4_port"
        $hook8 = "tcp4_seq_show"
        $hook9 = "tcp6_port"
        $hook10 = "tcp6_seq_show"
        $hook11 = "udp4_port"
        $hook12 = "udp4_seq_show"
        $hook13 = "udp6_port"
        $hook14 = "udp6_seq_show"
        $rk1 = "rootkit"
        $rk2 = "dropper"
        $rk3 = "hide"
        $rk4 = "hook"
        $rk5 = "hacked"
    condition:
        2 of ($str*) and 1 of ($init*) and 3 of ($hook*) and 3 of ($rk*)
}

rule Linux_Rootkit_Generic_f07bcabe {
    meta:
        author = "Elastic Security"
        id = "f07bcabe-f91e-4872-8677-dee6307e79d0"
        fingerprint = "7335426e705383ff6f62299943a139390b83ce2af4cbfc145cfe78c0f0015a26"
        creation_date = "2024-12-02"
        last_modified = "2024-12-09"
        threat_name = "Linux.Rootkit.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "fh_install_hook"
        $str2 = "fh_remove_hook"
        $str3 = "fh_resolve_hook_address"
    condition:
        2 of them
}

rule Linux_Rootkit_Generic_5d17781b {
    meta:
        author = "Elastic Security"
        id = "5d17781b-5d2a-4405-8806-274e6cabfe2c"
        fingerprint = "220eff54c80a69c3df0d8f71aeacdd114cc2ea0675595c2bfde2ac47578c3a02"
        creation_date = "2024-12-02"
        last_modified = "2025-06-10"
        threat_name = "Linux.Rootkit.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str = "kallsyms_lookup_name_t"
        $lic1 = "license=Dual BSD/GPL"
        $lic2 = "license=GPL"
    condition:
        $str and 1 of ($lic*)
}

