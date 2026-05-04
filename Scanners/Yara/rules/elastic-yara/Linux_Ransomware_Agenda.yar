rule Linux_Ransomware_Agenda_4562a654 {
    meta:
        author = "Elastic Security"
        id = "4562a654-a595-4480-a095-bd89ec907529"
        fingerprint = "b290b47e0839a5563b86d9d7dfbdc7fb2efa5669ede07f3710031f251b82ed6b"
        creation_date = "2024-09-12"
        last_modified = "2024-11-22"
        threat_name = "Linux.Ransomware.Agenda"
        reference_sample = "cd27a31e618fe93df37603e5ece3352a91f27671ee73bdc8ce9ad793cad72a0f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $ = "%s_RECOVER.txt"
        $ = "-- Qilin"
        $ = "no-vm-kill"
        $ = "File extensions blacklist: [%s]"
    condition:
        3 of them
}

