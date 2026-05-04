rule Windows_Trojan_Revcoderat_8e6d4182 {
    meta:
        author = "Elastic Security"
        id = "8e6d4182-4ea8-4d4c-ad3a-d16b42e387f4"
        fingerprint = "bc259d888e913dffb4272e2f871592238eb78922989d30ac4dc23cdeb988cc78"
        creation_date = "2021-09-02"
        last_modified = "2022-01-13"
        threat_name = "Windows.Trojan.Revcoderat"
        reference_sample = "77732e74850050bb6f935945e510d32a0499d820fa1197752df8bd01c66e8210"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "PLUGIN_PROCESS_REVERSE_PROXY: Plugin already exists, skipping download!" ascii fullword
        $a2 = "TARGET_HOST_UPDATE(): Sync successful!" ascii fullword
        $a3 = "WEBCAM_ACTIVATE: Plugin already exists, skipping download!" ascii fullword
        $a4 = "send_keylog_get" ascii fullword
    condition:
        all of them
}

