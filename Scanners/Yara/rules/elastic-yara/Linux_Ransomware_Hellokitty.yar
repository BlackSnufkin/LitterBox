rule Linux_Ransomware_Hellokitty_35731270 {
    meta:
        author = "Elastic Security"
        id = "35731270-b283-4dff-8316-6a541ff1d4d5"
        fingerprint = "1945bfcbe084f8f6671c73e74679fb2933d2ebea54479fdf348d4804a614279a"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Hellokitty"
        reference_sample = "556e5cb5e4e77678110961c8d9260a726a363e00bf8d278e5302cb4bfccc3eed"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "File Locked:%s PID:%d" fullword
        $a2 = "error encrypt: %s rename back:%s" fullword
        $a3 = "esxcli vm process kill -t=soft -w=%d" fullword
    condition:
        2 of them
}

