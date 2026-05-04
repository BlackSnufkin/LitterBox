rule Multi_AttackSimulation_Blindspot_d93f54c5 {
    meta:
        author = "Elastic Security"
        id = "d93f54c5-6574-4999-a3c0-39ef688b28dc"
        fingerprint = "4ec38f841aa4dfe32b1f6b6cd2e361c7298839ef1e983061cb90827135f34a58"
        creation_date = "2022-05-23"
        last_modified = "2022-08-16"
        threat_name = "Multi.AttackSimulation.Blindspot"
        severity = 1
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a = "\\\\.\\pipe\\blindspot-%d."
    condition:
        all of them
}

