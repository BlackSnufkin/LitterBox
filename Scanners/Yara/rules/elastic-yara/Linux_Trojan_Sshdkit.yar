rule Linux_Trojan_Sshdkit_18a0b82a {
    meta:
        author = "Elastic Security"
        id = "18a0b82a-94ff-4328-bfa7-25034f170522"
        fingerprint = "9bd28a490607b75848611389b39cf77229cfdd1e885f23c5439d49773924ce16"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Sshdkit"
        reference_sample = "003245047359e17706e4504f8988905a219fcb48865afea934e6aafa7f97cef6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 06 2A CA 37 F2 31 18 0E 2F 47 CD 87 9D 16 3F 6D }
    condition:
        all of them
}

