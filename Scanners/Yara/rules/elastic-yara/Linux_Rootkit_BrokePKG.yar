rule Linux_Rootkit_BrokePKG_7b7d4581 {
    meta:
        author = "Elastic Security"
        id = "7b7d4581-ee4d-48c3-81e4-4264d68e8fe9"
        fingerprint = "5d771035e2bc4ffea1b9fd6f29c76ff5d9278db42167d3dab90eb0ac8d4bdd78"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.BrokePKG"
        reference_sample = "97c5e011c7315a05c470eef4032030e461ec2a596513703beedeec0b0c6ed2da"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $license1 = "author=R3tr074"
        $license2 = "name=brokepkg"
        $license3 = "description=Rootkit"
        $license4 = "license=GPL"
        $str1 = "brokepkg"
        $str2 = "brokepkg: module revealed"
        $str3 = "brokepkg: hidden module"
        $str4 = "brokepkg: given away root"
        $str5 = "brokepkg unloaded, my work has completed"
        $str6 = "br0k3_n0w_h1dd3n"
        $hook1 = "nf_inet_hooks"
        $hook2 = "ftrace_hook"
        $hook3 = "hook_getdents"
        $hook4 = "hook_kill"
        $hook5 = "hook_tcp4_seq_show"
        $hook6 = "hook_tcp6_seq_show"
        $hook7 = "orig_tcp6_seq_show"
        $hook8 = "orig_tcp4_seq_show"
        $hook9 = "orig_kill"
        $hook10 = "orig_getdents"
    condition:
        3 of ($license*) or 2 of ($str*) or 4 of ($hook*)
}

