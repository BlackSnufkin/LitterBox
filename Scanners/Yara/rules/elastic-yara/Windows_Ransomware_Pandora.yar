rule Windows_Ransomware_Pandora_bca8ce23 {
    meta:
        author = "Elastic Security"
        id = "bca8ce23-6722-4cda-b5fa-623eda4fca1b"
        fingerprint = "0da732f6bdf24f35dee3c1bf85435650a5ce9b5c6a93f01176659943c01ad711"
        creation_date = "2022-03-14"
        last_modified = "2022-04-12"
        threat_name = "Windows.Ransomware.Pandora"
        reference_sample = "2c940a35025dd3847f7c954a282f65e9c2312d2ada28686f9d1dc73d1c500224"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "/c vssadmin.exe delete shadows /all /quiet" wide fullword
        $a2 = "\\Restore_My_Files.txt" wide fullword
        $a3 = ".pandora" wide fullword
    condition:
        all of them
}

