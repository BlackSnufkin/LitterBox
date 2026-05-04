rule Linux_Rootkit_Melofee_25d42bdd {
    meta:
        author = "Elastic Security"
        id = "25d42bdd-f6ee-458c-a102-7123225f0be2"
        fingerprint = "964cf1d468b829064c681c6b22bce00c4ef3536243fc5d1bac16879e0b68d9b2"
        creation_date = "2024-11-14"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Melofee"
        reference_sample = "5830862707711a032728dfa6a85c904020766fa316ea85b3eef9c017f0e898cc"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "hide_proc"
        $str2 = "find_hide_name"
        $str3 = "hide_module"
        $str4 = "unhide_chdir"
        $str5 = "hide_content"
        $str6 = "hidden_chdirs"
        $str7 = "hidden_tcp_conn"
        $str8 = "HIDETAGOUT"
        $str9 = "HIDETAGIN"
    condition:
        4 of them
}

