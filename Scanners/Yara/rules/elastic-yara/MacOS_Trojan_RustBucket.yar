rule MacOS_Trojan_RustBucket_e64f7a92 {
    meta:
        author = "Elastic Security"
        id = "e64f7a92-e530-4d0b-8ecb-fe5756ad648c"
        fingerprint = "f9907f46c345a874b683809f155691723e3a6df7c48f6f4e6eb627fb3dd7904d"
        creation_date = "2023-06-26"
        last_modified = "2023-06-29"
        threat_name = "MacOS.Trojan.RustBucket"
        reference = "https://www.elastic.co/security-labs/DPRK-strikes-using-a-new-variant-of-rustbucket"
        reference_sample = "9ca914b1cfa8c0ba021b9e00bda71f36cad132f27cf16bda6d937badee66c747"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $user_agent = "User-AgentMozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)"
        $install_log = "/var/log/install.log"
        $timestamp = "%Y-%m-%d %H:%M:%S"
    condition:
        all of them
}

