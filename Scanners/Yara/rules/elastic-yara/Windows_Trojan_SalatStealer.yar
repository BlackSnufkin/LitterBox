rule Windows_Trojan_SalatStealer_03d2a4ee {
    meta:
        author = "Elastic Security"
        id = "03d2a4ee-8197-454b-9126-be17f55d25f0"
        fingerprint = "aea05696530ed05d7310cd3ed5bc3f4fe4c50d50960de54bd0a0f94770b9b008"
        creation_date = "2026-02-11"
        last_modified = "2026-03-17"
        threat_name = "Windows.Trojan.SalatStealer"
        reference_sample = "2fff2a112d0283b6ecc2f73366b31d305cbebb8d06c88ceba060dc76eb7f5a4c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "main.getGeckoCookies" ascii fullword
        $a2 = "main.getChromeAutofils" ascii fullword
        $a3 = "main.runKeylogger" ascii fullword
        $a4 = "salat/task.go" ascii fullword
        $a5 = "salat/screenshot.CaptureRect" ascii fullword
    condition:
        all of them
}

