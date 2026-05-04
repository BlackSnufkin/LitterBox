rule Linux_Rootkit_Mobkit_335e48bc {
    meta:
        author = "Elastic Security"
        id = "335e48bc-03e2-486e-a8e8-bcf1aaf9302d"
        fingerprint = "226fbd5530634622c2fb8d9e08d29d184c5c01aea6140e08b8be2f11b78b34b6"
        creation_date = "2025-03-11"
        last_modified = "2025-03-19"
        threat_name = "Linux.Rootkit.Mobkit"
        reference_sample = "aa62bbf83a54b5c908609e69cfee37dfeb9c5f2f75529f2d1009a6dba9e87b9f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $meta1 = "name=mob"
        $meta2 = "author=shv-om"
        $meta3 = "description=MobKit"
        $meta4 = "license=GPL"
        $hook1 = "real_kallsyms_lookup_name"
        $hook2 = "unregister_kprobe"
        $hook3 = "ftrace_set_filter_ip"
        $hook4 = "unregister_ftrace_function"
        $hook5 = "orig_kill"
        $hook6 = "call_usermodehelper"
        $str1 = "mob.mod.c"
        $str2 = "mob_drivers"
        $str3 = "mob: Prevented direct recursion via parent_ip check"
        $str4 = "mob: Hooking %s at address: %px with handler %px"
        $str5 = "mob: [INFO] Module unloaded -> Work Queue Destroyed"
    condition:
        (3 of ($meta*)) or (4 of ($str*)) or (all of ($hook*)) or ((3 of ($hook*) and 3 of ($str*)))
}

