rule MacOS_Trojan_XScreen_7837ad6c {
    meta:
        author = "Elastic Security"
        id = "7837ad6c-18b6-4b76-87fd-cb740215282c"
        fingerprint = "560f2bfc1a42425db853948113c0d11f63728cc495dbd0e7be0e7726653ec13a"
        creation_date = "2026-02-25"
        last_modified = "2026-04-06"
        threat_name = "MacOS.Trojan.XScreen"
        reference_sample = "432c720a9ada40785d77cd7e5798de8d43793f6da31c5e7b3b22ee0a451bb249"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "/Users/Shared/._cfg" ascii fullword
        $a2 = "base64EncodedStringWithOptions:" ascii fullword
        $a3 = "/private/tmp/google_cache.db" ascii fullword
        $a4 = "[hyphen]" ascii fullword
        $a5 = "generalPasteboard" ascii fullword
    condition:
        all of them
}

