rule MacOS_Trojan_Eggshell_ddacf7b9 {
    meta:
        author = "Elastic Security"
        id = "ddacf7b9-8479-47ef-9df2-17060578a8e5"
        fingerprint = "2e6284c8e44809d5f88781dcf7779d1e24ce3aedd5e8db8598e49c01da63fe62"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Eggshell"
        reference_sample = "6d93a714dd008746569c0fbd00fadccbd5f15eef06b200a4e831df0dc8f3d05b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "ScreenshotThread" ascii fullword
        $a2 = "KeylogThread" ascii fullword
        $a3 = "GetClipboardThread" ascii fullword
        $a4 = "_uploadProgress" ascii fullword
        $a5 = "killTask:" ascii fullword
    condition:
        all of them
}

