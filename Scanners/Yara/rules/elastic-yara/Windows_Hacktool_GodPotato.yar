rule Windows_Hacktool_GodPotato_5f1aad81 {
    meta:
        author = "Elastic Security"
        id = "5f1aad81-88d8-4561-a6f9-d7521b9ffdf5"
        fingerprint = "3645a259f9b5d07bd5ad2ec823fd704eccd0412dd75c47bc82124db9a907da2a"
        creation_date = "2024-06-24"
        last_modified = "2024-07-02"
        threat_name = "Windows.Hacktool.GodPotato"
        reference_sample = "00171bb6e9e4a9b8601e988a8c4ac6f5413e31e1b6d86d24b0b53520cd02184c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "GodPotato" wide fullword
        $a2 = "GodPotatoContext was not initialized" wide fullword
        $a3 = "GodPotatoStorageTrigger" ascii fullword
        $a4 = "[*] DCOM obj GUID: {0}" wide fullword
        $a5 = "[*] DispatchTable: 0x{0:x}" wide fullword
        $a6 = "[*] UseProtseqFunction: 0x{0:x}" wide fullword
        $a7 = "[*] process start with pid {0}" wide fullword
        $a8 = "[!] ImpersonateNamedPipeClient fail error:{0}" wide fullword
        $a9 = "[*] CoGetInstanceFromIStorage: 0x{0:x}" wide fullword
        $a10 = "[*] Trigger RPCS" wide
    condition:
        5 of them
}

