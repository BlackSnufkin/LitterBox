rule Linux_Trojan_Orbit_57c23178 {
    meta:
        author = "Elastic Security"
        id = "57c23178-1345-47b7-97b1-aa2075d9d69d"
        fingerprint = "0bb1c74f872ea8778a442aafc2c6f3f04e331b7f743ba726257e36b09ef33da4"
        creation_date = "2022-07-20"
        last_modified = "2022-08-16"
        threat_name = "Linux.Trojan.Orbit"
        reference_sample = "40b5127c8cf9d6bec4dbeb61ba766a95c7b2d0cafafcb82ede5a3a679a3e3020"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $loaderstrings0 = "shred"
        $loaderstrings1 = "newpath" fullword
        $loaderstrings2 = "shm update" fullword
        $loaderstrings3 = "cp -p %s /dev/shm/ldx/.backup_ld.so" fullword
        $loaderstrings4 = "/dev/shm/ldx/libdl.so\n" fullword
        $loaderstrings5 = "oldpath: %s newpath: %s\n" fullword
        $loaderstrings6 = "can't locate oldpath" fullword
        $loaderstrings7 = "specify dir" fullword
        $loaderstrings8 = "/sshpass.txt"
        $loaderstrings9 = "/sshpass2.txt"
        $loaderstrings10 = "/.logpam"
        $loaderstrings11 = "/.boot.sh"
        $tmppath = "/tmp/.orbit" fullword
        $functionName0 = "tcp_port_hidden" fullword
        $functionName1 = "clean_ports" fullword
        $functionName2 = "remove_port" fullword
        $execvStrings0 = "[%s] [%s] [BLOCKED] %s " fullword
        $execvStrings1 = "[%s] [%s] %s " fullword
        $execvStrings2 = "%m-%d %H:%M:%S" fullword
        $pam_log_password = { 8B 45 F8 48 98 C6 84 05 F0 FE FF FF 00 48 8D 85 F0 FE FF FF B9 A4 01 00 00 BA 42 04 00 00 48 89 C6 BF 02 00 00 00 B8 00 00 00 00 E8 B6 C2 FE FF 89 45 F4 48 8B 8D E0 FE FF FF 48 8B 95 E8 FE FF FF 48 8D 85 F0 FE FF FF }
        $load_hidden_ports = { 48 8B 45 ?? BE 0A 00 00 00 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 83 7D ?? 00 75 }
        $hosts_access = { 8B 45 ?? 48 98 C6 84 05 D0 EF FF FF 00 48 8B 05 ?? ?? ?? ?? 48 8B 80 ?? ?? 00 00 48 8B 95 C8 EF FF FF 48 89 D7 FF D0 89 45 ?? 48 8D 85 D0 EF FF FF 48 89 45 ?? EB }
    condition:
        7 of ($loaderstrings*) or (all of ($functionName*) and $tmppath and all of ($execvStrings*)) or 2 of ($pam_log_password, $load_hidden_ports, $hosts_access)
}

