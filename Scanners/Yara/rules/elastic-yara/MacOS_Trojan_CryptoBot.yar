rule MacOS_Trojan_CryptoBot_041723c8 {
    meta:
        author = "Elastic Security"
        id = "041723c8-9de4-4100-8db6-4a3415a3dcdd"
        fingerprint = "840ca6dc09f015aee3a1fb02de4ae5b6b65beeba3c9b4746e4b5d68972f20782"
        creation_date = "2026-02-24"
        last_modified = "2026-04-06"
        threat_name = "MacOS.Trojan.CryptoBot"
        reference_sample = "ad21af758af28b7675c55e64bf5a9b3318f286e4963ff72470a311c2e18f42ff"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "main.getBrowserDataPath" ascii fullword
        $a2 = "main.isSolanaAddress" ascii fullword
        $a3 = "main.killProcess" ascii fullword
        $a4 = "main.postEncryptedData" ascii fullword
        $a5 = "main.buildServerUrl" ascii fullword
        $a6 = "/Users/Shared/Dev/src/other/Crypto-Bot/constants.go" ascii fullword
    condition:
        4 of them
}

