rule Windows_Trojan_Farfli_85d1bcc9 {
    meta:
        author = "Elastic Security"
        id = "85d1bcc9-c3c7-454c-a77f-0e0de933c4c3"
        fingerprint = "56a5e4955556d08b80849ea5775f35f5a32999d6b5df92357ab142a4faa74ac3"
        creation_date = "2022-02-17"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Farfli"
        reference_sample = "e3e9ea1b547cc235e6f1a78b4ca620c69a54209f84c7de9af17eb5b02e9b58c3"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { AB 66 AB C6 45 D4 25 C6 45 D5 73 C6 45 D6 5C C6 45 D7 25 C6 45 }
    condition:
        all of them
}

