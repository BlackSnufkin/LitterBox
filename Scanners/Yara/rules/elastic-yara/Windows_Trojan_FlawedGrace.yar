rule Windows_Trojan_FlawedGrace_8c5eb04b {
    meta:
        author = "Elastic Security"
        id = "8c5eb04b-301b-4d05-a010-3329e5b764c6"
        fingerprint = "46ce025974792cdefe9d4f4493cee477c0eaf641564cd44becd687c27d9e7c30"
        creation_date = "2023-11-01"
        last_modified = "2023-11-02"
        threat_name = "Windows.Trojan.FlawedGrace"
        reference_sample = "966112f3143d751a95c000a990709572ac8b49b23c0e57b2691955d6fda1016e"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Grace finalized, no more library calls allowed." ascii fullword
        $a2 = ".?AVReadThread@TunnelIO@NS@@" ascii fullword
        $a3 = ".?AVTunnelClientDirectIO@NS@@" ascii fullword
        $a4 = ".?AVWireClientConnectionThread@NS@@" ascii fullword
        $a5 = ".?AVWireParam@NS@@" ascii fullword
    condition:
        3 of them
}

