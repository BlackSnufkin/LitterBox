rule Linux_Backdoor_Python_00606bac {
    meta:
        author = "Elastic Security"
        id = "00606bac-83eb-4a58-82d2-e4fd16d30846"
        fingerprint = "cce1d0e7395a74c04f15ff95f6de7fd7d5f46ede83322b832df74133912c0b17"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Backdoor.Python"
        reference_sample = "b3e3728d43535f47a1c15b915c2d29835d9769a9dc69eb1b16e40d5ba1b98460"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F4 01 83 45 F8 01 8B 45 F8 0F B6 00 84 C0 75 F2 83 45 F8 01 8B }
    condition:
        all of them
}

