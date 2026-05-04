rule Windows_PUP_Veriato_fae5978c {
    meta:
        author = "Elastic Security"
        id = "fae5978c-f26c-4215-9407-d16e492ab5c1"
        fingerprint = "8d351cdd11d6dddc76cd89e7de9e65b28ef5c8183db804b2a450095e2f3214e5"
        creation_date = "2022-06-08"
        last_modified = "2022-09-29"
        threat_name = "Windows.PUP.Veriato"
        reference_sample = "53f09e60b188e67cdbf28bda669728a1f83d47b0279debf3d0a8d5176479d17f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s1 = "InitializeDll" fullword
        $a1 = "C:\\Windows\\winipbin\\svrltmgr.dll" fullword
        $a2 = "C:\\Windows\\winipbin\\svrltmgr64.dll" fullword
    condition:
        $s1 and ($a1 or $a2)
}

