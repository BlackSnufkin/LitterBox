rule Linux_Rootkit_Diamorphine_716c7ffa {
    meta:
        author = "Elastic Security"
        id = "716c7ffa-ea57-4ac2-9d23-9873bc8f83bd"
        fingerprint = "59f9657c8ee1f6d05020a3565d08230d10185968c8b064f462ee54a4db8db3d6"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Diamorphine"
        reference_sample = "01fb490fbe2c2b5368cc227abd97e011e83b5e99bb80945ef599fc80e85f8545"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "author=m0nad"
        $str2 = "description=LKM rootkit"
        $str3 = "name=diamorphine"
        $license1 = "license=Dual BSD/GPL"
        $license2 = "license=GPL"
    condition:
        2 of ($str*) and 1 of ($license*)
}

rule Linux_Rootkit_Diamorphine_66eb93c7 {
    meta:
        author = "Elastic Security"
        id = "66eb93c7-3f26-43ce-b43e-550c6fd44927"
        fingerprint = "e045a6f3359443a11fa609eefedb0aa92f035e91e087e3472461c10bb28f0cc1"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Diamorphine"
        reference_sample = "01fb490fbe2c2b5368cc227abd97e011e83b5e99bb80945ef599fc80e85f8545"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $rk1 = "sys_call_table"
        $rk2 = "kallsyms_lookup_name"
        $rk3 = "retpoline=Y"
        $func1 = "get_syscall_table_bf"
        $func2 = "is_invisible"
        $func3 = "hacked_getdents64"
        $func4 = "orig_getdents64"
        $func5 = "give_root"
        $func6 = "module_show"
        $func7 = "module_hide"
        $func8 = "hacked_kill"
        $func9 = "write_cr0_forced"
    condition:
        1 of ($rk*) and 3 of ($func*)
}

