rule Windows_Ransomware_Generic_99f5a632 {
    meta:
        author = "Elastic Security"
        id = "99f5a632-8562-4321-b707-c5f583b14511"
        fingerprint = "84ab8d177e50bce1a3eceb99befcf05c7a73ebde2f7ea4010617bf4908257fdb"
        creation_date = "2022-02-24"
        last_modified = "2022-02-24"
        threat_name = "Windows.Ransomware.Generic"
        reference_sample = "4dc13bb83a16d4ff9865a51b3e4d24112327c526c1392e14d56f20d6f4eaf382"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "stephanie.jones2024@protonmail.com"
        $a2 = "_/C_/projects/403forBiden/wHiteHousE.init" ascii fullword
        $a3 = "All your files, documents, photoes, videos, databases etc. have been successfully encrypted" ascii fullword
        $a4 = "<p>Do not try to decrypt then by yourself - it's impossible" ascii fullword
    condition:
        all of them
}

