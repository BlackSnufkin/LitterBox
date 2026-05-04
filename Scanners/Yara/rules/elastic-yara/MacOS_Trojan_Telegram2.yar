rule MacOS_Trojan_Telegram2_973b46bd {
    meta:
        author = "Elastic Security"
        id = "973b46bd-a273-4477-bbd7-a150501016a6"
        fingerprint = "cb3eaa2b484ef153bc43b1a8511807680aab87701d8dbeb4e2d7abd8de95016f"
        creation_date = "2026-02-25"
        last_modified = "2026-04-06"
        threat_name = "MacOS.Trojan.Telegram2"
        reference_sample = "080a52b99d997e1ac60bd096a626b4d7c9253f0c7b7c4fc8523c9d47a71122af"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "poEchoCmd" ascii fullword
        $a2 = "poEvalCommand" ascii fullword
        $a3 = "poParentStreams" ascii fullword
        $a4 = "poInteractive" ascii fullword
        $a5 = "sendPacketNimAsyncContinue" ascii fullword
        $a6 = "trojan1.nim" ascii fullword
        $a7 = "information.nim" ascii fullword
    condition:
        5 of them
}

