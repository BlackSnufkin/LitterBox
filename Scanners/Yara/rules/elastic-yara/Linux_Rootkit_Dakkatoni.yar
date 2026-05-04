rule Linux_Rootkit_Dakkatoni_010d3ac2 {
    meta:
        author = "Elastic Security"
        id = "010d3ac2-0bb2-4966-bf5f-fd040ba07311"
        fingerprint = "2c7935079dc971d2b8a64c512ad677e946ff45f7f1d1b62c3ca011ebde82f13b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Rootkit.Dakkatoni"
        reference_sample = "38b2d033eb5ce87faa4faa7fcac943d9373e432e0d45e741a0c01d714ee9d4d3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 C8 C1 E0 0D 31 C1 89 CE 83 E6 03 83 C6 05 89 C8 31 D2 C1 }
    condition:
        all of them
}

