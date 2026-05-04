rule Linux_Rootkit_Fontonlake_8fa41f5e {
    meta:
        author = "Elastic Security"
        id = "8fa41f5e-d03d-4647-86fb-335e056c1c0d"
        fingerprint = "187aae8e659061a06b44e0d353e35e22ada9076c78d8a7e4493e1e4cc600bc9d"
        creation_date = "2021-10-12"
        last_modified = "2022-01-26"
        threat_name = "Linux.Rootkit.Fontonlake"
        reference_sample = "826222d399e2fb17ae6bc6a4e1493003881b1406154c4b817f0216249d04a234"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "kernel_write" fullword
        $a2 = "/proc/.dot3" fullword
        $a3 = "hide_pid" fullword
        $h2 = "s_hide_pids" fullword
        $h3 = "s_hide_tcp4_ports" fullword
        $h4 = "s_hide_strs" fullword
        $tmp1 = "/tmp/.tmH" fullword
        $tmp2 = "/tmp/.tmp_" fullword
    condition:
        (all of ($a*) and 1 of ($tmp*)) or (all of ($h*))
}

