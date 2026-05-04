rule Windows_Infostealer_NovaBlight_b80703b9 {
    meta:
        author = "Elastic Security"
        id = "b80703b9-9a23-43b4-b28b-c6da29e4f414"
        fingerprint = "492a380d919e191b07e748b09fa89dd9c5addef5635bd5b623363dd748df1cc5"
        creation_date = "2025-07-18"
        last_modified = "2025-07-28"
        threat_name = "Windows.Infostealer.NovaBlight"
        reference_sample = "d806d6b5811965e745fd444b8e57f2648780cc23db9aa2c1675bc9d18530ab73"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "C:\\Users\\Administrateur\\Desktop\\Nova\\"
        $a2 = "[+] Recording..." fullword
        $a3 = "[+] Capture start" fullword
    condition:
        all of them
}

