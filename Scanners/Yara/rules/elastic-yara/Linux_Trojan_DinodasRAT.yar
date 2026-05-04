rule Linux_Trojan_DinodasRAT_1d371d10 {
    meta:
        author = "Elastic Security"
        id = "1d371d10-b2ae-4ea0-ad37-f5a5a571a6fc"
        fingerprint = "a53bf582ad95320dd6f432cb7290ce604aa558e4ecf6ae4e11d7985183969db1"
        creation_date = "2024-04-02"
        last_modified = "2024-06-12"
        threat_name = "Linux.Trojan.DinodasRAT"
        reference_sample = "bf830191215e0c8db207ea320d8e795990cf6b3e6698932e6e0c9c0588fc9eff"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $s1 = "int MyShell::createsh()"
        $s2 = "/src/myshell.cpp"
        $s3 = "/src/inifile.cpp"
        $s4 = "Linux_%s_%s_%u_V"
        $s5 = "/home/soft/mm/rootkit/"
        $s6 = "IniFile::load_ini_file"
    condition:
        4 of them
}

