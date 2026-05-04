rule Linux_Ransomware_Lockbit_d248e80e {
    meta:
        author = "Elastic Security"
        id = "d248e80e-3e2f-4957-adc3-0c912b0cd386"
        fingerprint = "417ecf5a0b6030ed5b973186efa1e72dfa56886ba6cfc5fbf615e0814c24992f"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Lockbit"
        reference_sample = "4800a67ceff340d2ab4f79406a01f58e5a97d589b29b35394b2a82a299b19745"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "restore-my-files.txt" fullword
        $b1 = "xkeyboard-config" fullword
        $b2 = "bootsect.bak" fullword
        $b3 = "lockbit" fullword
        $b4 = "Error: %s" fullword
        $b5 = "crypto_generichash_blake2b_final" fullword
    condition:
        $a1 and 2 of ($b*)
}

rule Linux_Ransomware_Lockbit_5b30a04b {
    meta:
        author = "Elastic Security"
        id = "5b30a04b-d618-4698-a797-30bf6d4a001c"
        fingerprint = "99bf6afb1554ec3b3b82389c93ca87018c51f7a80270d64007a5f5fc59715c45"
        creation_date = "2023-07-29"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Lockbit"
        reference_sample = "41cbb7d79388eaa4d6e704bd4a8bf8f34d486d27277001c343ea3ce112f4fb0d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 5D 50 4A 49 55 58 40 77 58 54 5C }
        $a2 = { 33 6B 5C 5A 4C 4B 4A 50 4F 5C 55 40 }
        $a3 = { 5E 4C 58 4B 58 57 4D 5C 5C 5D }
    condition:
        all of them
}

