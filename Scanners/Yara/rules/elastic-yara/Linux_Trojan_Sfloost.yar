rule Linux_Trojan_Sfloost_69a5343a {
    meta:
        author = "Elastic Security"
        id = "69a5343a-4885-4d88-9eaf-ddfcc95e1f39"
        fingerprint = "c19368bf04e4b67537a8573b5beba56bab8bcfdf870640ef5bd46d40735ee539"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Sfloost"
        reference_sample = "c0cd73db5165671c7bbd9493c34d693d25b845a9a21706081e1bf44bf0312ef9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 0F 83 C8 50 88 43 0C 0F B6 45 F0 66 C7 43 10 00 00 66 C7 43 12 }
    condition:
        all of them
}

