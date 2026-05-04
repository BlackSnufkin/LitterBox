rule Windows_Ransomware_Lockfile_74185716 {
    meta:
        author = "Elastic Security"
        id = "74185716-e79d-4d63-b6ae-9480f24dcd4f"
        fingerprint = "849a0fb5a2e08b2d32db839a7fdbde03a184a48726678e65e7f8452b354a3ca8"
        creation_date = "2021-08-31"
        last_modified = "2022-01-13"
        threat_name = "Windows.Ransomware.Lockfile"
        reference_sample = "bf315c9c064b887ee3276e1342d43637d8c0e067260946db45942f39b970d7ce"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "LOCKFILE-README"
        $a2 = "wmic process where \"name  like '%virtualbox%'\" call terminate"
        $a3 = "</computername>"
        $a4 = ".lockfile"
    condition:
        all of them
}

