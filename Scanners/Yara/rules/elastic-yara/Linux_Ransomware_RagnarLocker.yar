rule Linux_Ransomware_RagnarLocker_9f5982b8 {
    meta:
        author = "Elastic Security"
        id = "9f5982b8-98db-42d1-b987-451d3cb7fc4b"
        fingerprint = "782d9225a6060c23484a285f7492bb45f21c37597ea82e4ca309aedbb1c30223"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.RagnarLocker"
        reference_sample = "f668f74d8808f5658153ff3e6aee8653b6324ada70a4aa2034dfa20d96875836"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = ".README_TO_RESTORE"
        $a2 = "If WE MAKE A DEAL:"
        $a3 = "Unable to rename file from: %s to: %s"
    condition:
        2 of them
}

