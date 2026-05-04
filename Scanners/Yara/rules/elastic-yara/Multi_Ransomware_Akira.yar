rule Multi_Ransomware_Akira_21842eb3 {
    meta:
        author = "Elastic Security"
        id = "21842eb3-9ccc-4dec-9536-37791ef79714"
        fingerprint = "62f1a985bb718fa27c56d2f23d4f36a5b90b35626f0ef5def83441d27122a503"
        creation_date = "2024-11-21"
        last_modified = "2024-11-22"
        threat_name = "Multi.Ransomware.Akira"
        reference_sample = "3298d203c2acb68c474e5fdad8379181890b4403d6491c523c13730129be3f75"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "Well, for now let's keep all the tears and resentment to ourselves"
    condition:
        all of them
}

