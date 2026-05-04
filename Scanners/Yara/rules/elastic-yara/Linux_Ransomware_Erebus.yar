rule Linux_Ransomware_Erebus_ead4f55b {
    meta:
        author = "Elastic Security"
        id = "ead4f55b-a4c6-46ff-bc8e-03831a17df9c"
        fingerprint = "571832cc76322a95244b042ab9b358755a1be19260410658dc32c03c5cae7638"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Erebus"
        reference_sample = "6558330f07a7c90c40006346ed09e859b588d031193f8a9679fe11a85c8ccb37"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "important files have been encrypted"
        $a2 = "max_size_mb"
        $a3 = "EREBUS IS BEST."
    condition:
        2 of them
}

