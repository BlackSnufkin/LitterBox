rule Windows_Trojan_ArkeiStealer_84c7086a {
    meta:
        author = "Elastic Security"
        id = "84c7086a-abc3-4b97-b325-46a078b90a95"
        fingerprint = "f1d701463b0001de8996b30d2e36ddecb93fe4ca2a1a26fc4fcdaeb0aa3a3d6d"
        creation_date = "2022-02-17"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.ArkeiStealer"
        reference_sample = "708d9fb40f49192d4bf6eff62e0140c920a7eca01b9f78aeaf558bef0115dbe2"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 01 89 55 F4 8B 45 F4 3B 45 10 73 31 8B 4D 08 03 4D F4 0F BE 19 8B }
    condition:
        all of them
}

