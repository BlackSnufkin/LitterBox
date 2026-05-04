rule Linux_Ransomware_Quantum_8513fb8b {
    meta:
        author = "Elastic Security"
        id = "8513fb8b-43f7-46b1-8318-5549a7609d3b"
        fingerprint = "1c1af76ab5df8243b8e25555f1762749ca60da56fecea9d4131c612358244525"
        creation_date = "2023-07-28"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Quantum"
        reference_sample = "3bcb9ad92fdca53195f390fc4d8d721b504b38deeda25c1189a909a7011406c9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "All your files are encrypted on all devices across the network"
        $a2 = "process with pid %d is blocking %s, going to kill it"
    condition:
        all of them
}

