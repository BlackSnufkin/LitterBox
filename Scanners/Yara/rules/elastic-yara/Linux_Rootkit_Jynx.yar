rule Linux_Rootkit_Jynx_c470eaff {
    meta:
        author = "Elastic Security"
        id = "c470eaff-20f2-430f-988f-15a4b7bd75f8"
        fingerprint = "337087ba691d4f535e7ee160efb60ca5b71c79504297f6e711bcaf058fdb7a36"
        creation_date = "2024-11-14"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Jynx"
        reference_sample = "79c2ae1a95b44f3df42d669cb44db606d2088c5c393e7de5af875f255865ecb4"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $hook1 = "old_access"
        $hook2 = "old_lxstat"
        $hook3 = "old_open"
        $hook4 = "old_rmdir"
        $hook5 = "old_unlink"
        $hook6 = "old_xstat"
        $hook7 = "old_fopen"
        $hook8 = "old_opendir"
        $hook9 = "old_readdir"
        $hook10 = "forge_proc_net_tcp"
        $hook11 = "forge_proc_cpu"
    condition:
        4 of ($hook*)
}

