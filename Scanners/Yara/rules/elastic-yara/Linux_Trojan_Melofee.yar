rule Linux_Trojan_Melofee_c23d18f3 {
    meta:
        author = "Elastic Security"
        id = "c23d18f3-caac-4d8a-8ecd-d1b831723648"
        fingerprint = "95bd1092104aa028b65b92d3dcf6af6deb019d00ef09e9c6570da39737fe3525"
        creation_date = "2024-11-14"
        last_modified = "2024-11-22"
        threat_name = "Linux.Trojan.Melofee"
        reference_sample = "b0abf6691e769ead1f11cfdcd300f8cd5291f19059be6bb40d556f793b1bc21e"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "hide ok"
        $str2 = "show ok"
        $str3 = "kill ok"
        $str4 = "wwwwwww"
        $str5 = "[md]"
        $str6 = "87JoENDi"
    condition:
        4 of them
}

