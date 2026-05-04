rule Macos_Trojan_NukeSped_de1ddb59 {
    meta:
        author = "Elastic Security"
        id = "de1ddb59-d640-4a5c-8b8b-49a668e8084c"
        fingerprint = "f69a659a603446cdaff1f77621358b0d643a1702bcc58174c61e77631f64925a"
        creation_date = "2026-01-09"
        last_modified = "2026-04-06"
        threat_name = "Macos.Trojan.NukeSped"
        reference_sample = "1418475d89f2dfe538083b85578f311b02428920132694a7a4e8e8a061b546ba"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $s_a = "GO_CHILD=1"
        $s_b = "t_loader/inject_mac.Inject"
        $s_c = "t_loader/common.init_env"
        $s_d = "common.save_config"
        $s_e = "/Library/SystemSettings/.CacheLogs.db"
        $rc4_key = { DE AD BE EF E7 74 89 23 D7 1E 4F BE EF E7 74 6F }
    condition:
        4 of ($s_*) or (3 of ($s_*) and $rc4_key)
}

