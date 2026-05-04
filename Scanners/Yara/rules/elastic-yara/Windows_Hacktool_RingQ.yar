rule Windows_Hacktool_RingQ_b9715540 {
    meta:
        author = "Elastic Security"
        id = "b9715540-77ae-4723-a29e-d4d88d626982"
        fingerprint = "f2a2d97b31cb648a6515dbf02a885a6afd434f38ed555c1e30296b7eb4550438"
        creation_date = "2024-06-28"
        last_modified = "2024-07-26"
        threat_name = "Windows.Hacktool.RingQ"
        reference_sample = "450e01c32618cd4e4a327147896352ed1b34dca9fb28389dba450acf95f8b735"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Loading Dir main.txt ..." ascii fullword
        $a2 = "Loading LocalFile ..." ascii fullword
        $a3 = "No Find main,txt and StringTable ..." ascii fullword
        $a4 = "https://github.com/T4y1oR/RingQ"
        $a5 = "RingQ :)" ascii fullword
        $a6 = "1. Create.exe fscan.exe" ascii fullword
        $a7 = "C:/Users/username/Documents/file.txt" ascii fullword
    condition:
        2 of them
}

