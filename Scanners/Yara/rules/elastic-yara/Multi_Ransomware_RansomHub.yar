rule Multi_Ransomware_RansomHub_4a8a07cd {
    meta:
        author = "Elastic Security"
        id = "4a8a07cd-700b-4514-a808-334c0a7641de"
        fingerprint = "c66b9c6889d0c4598bf2baa99a5d137a2e2ffd06dcd2141b08a6c1eec772a87c"
        creation_date = "2024-09-05"
        last_modified = "2024-09-30"
        threat_name = "Multi.Ransomware.RansomHub"
        reference_sample = "bfbbba7d18be1aa2e85390fa69a761302756ee9348b7343af6f42f3b5d0a939c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "white_files" ascii fullword
        $a2 = "note_file_name" ascii fullword
        $a3 = "note_short_text" ascii fullword
        $a4 = "set_wallpaper" ascii fullword
        $a5 = "local_disks" ascii fullword
        $a6 = "running_one" ascii fullword
        $a7 = "net_spread" ascii fullword
        $a8 = "kill_processes" ascii fullword
    condition:
        5 of them
}

