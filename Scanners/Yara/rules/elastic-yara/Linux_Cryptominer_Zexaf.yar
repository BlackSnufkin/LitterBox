rule Linux_Cryptominer_Zexaf_b90e7683 {
    meta:
        author = "Elastic Security"
        id = "b90e7683-84bf-4c07-b6ef-54c631280217"
        fingerprint = "4ca9fad98bdde19f71c117af9cb87007dc46494666e7664af111beded1100ae4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Cryptominer.Zexaf"
        reference_sample = "98650ebb7e463a06e737bcea4fd2b0f9036fafb0638ba8f002e6fe141b9fecfe"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 F2 C1 E7 18 C1 E2 18 C1 ED 08 09 D5 C1 EE 08 8B 14 24 09 FE }
    condition:
        all of them
}

