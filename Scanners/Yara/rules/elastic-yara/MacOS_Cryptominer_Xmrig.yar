rule MacOS_Cryptominer_Xmrig_241780a1 {
    meta:
        author = "Elastic Security"
        id = "241780a1-ad50-4ded-b85a-26339ae5a632"
        fingerprint = "be9c56f18e0f0bdc8c46544039b9cb0bbba595c1912d089b2bcc7a7768ac04a8"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Cryptominer.Xmrig"
        reference_sample = "2e94fa6ac4045292bf04070a372a03df804fa96c3b0cb4ac637eeeb67531a32f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "mining.set_target" ascii fullword
        $a2 = "XMRIG_HOSTNAME" ascii fullword
        $a3 = "Usage: xmrig [OPTIONS]" ascii fullword
        $a4 = "XMRIG_VERSION" ascii fullword
    condition:
        all of them
}

