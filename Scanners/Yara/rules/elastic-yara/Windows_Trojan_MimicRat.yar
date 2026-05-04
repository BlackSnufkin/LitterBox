rule Windows_Trojan_MimicRat_13eea89a {
    meta:
        author = "Elastic Security"
        id = "13eea89a-b466-424a-b553-b1fcde4255b9"
        fingerprint = "79ce75823fbd8ec20af38dfa91dce8789d3733040e1b64976d3626c175c3d53c"
        creation_date = "2026-02-13"
        last_modified = "2026-03-17"
        threat_name = "Windows.Trojan.MimicRat"
        reference_sample = "a508d0bb583dc6e5f97b6094f8f910b5b6f2b9d5528c04e4dee62c343fce6f4b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $b_0 = { 41 8B 56 18 49 8B 4E 10 41 89 46 08 }
        $b_1 = { 41 FF C0 48 FF C1 48 83 C2 4C 49 3B CA }
    condition:
        all of them
}

