rule MacOS_Backdoor_Keyboardrecord_832f7bac {
    meta:
        author = "Elastic Security"
        id = "832f7bac-3896-4934-b05f-8215a41cca74"
        fingerprint = "27aa4380bda0335c672e957ba2ce6fd1f42ccf0acd2eff757e30210c3b4fb2fa"
        creation_date = "2021-11-11"
        last_modified = "2022-07-22"
        threat_name = "MacOS.Backdoor.Keyboardrecord"
        reference_sample = "570cd76bf49cf52e0cb347a68bdcf0590b2eaece134e1b1eba7e8d66261bdbe6"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $s1 = "com.ccc.keyboardrecord"
        $s2 = "com.ccc.write_queue"
        $s3 = "ps -p %s > /dev/null"
        $s4 = "useage %s path useragentpid"
        $s5 = "keyboardRecorderStartPKc"
    condition:
        3 of them
}

