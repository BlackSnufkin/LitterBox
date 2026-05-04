rule Windows_Infostealer_PhemedroneStealer_bed8ea8a {
    meta:
        author = "Elastic Security"
        id = "bed8ea8a-f2a3-4a51-ae57-4986da4d21aa"
        fingerprint = "29702a2dc8b20c230ffef00dfff725133b707e35523e075ff85484a20da3c760"
        creation_date = "2024-03-21"
        last_modified = "2024-05-08"
        threat_name = "Windows.Infostealer.PhemedroneStealer"
        reference_sample = "38279fdad25c7972be9426cadb5ad5e3ee7e9761b0a41ed617945cb9a3713702"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "<KillDebuggers>b_"
        $a2 = "<Key3Database>b_"
        $a3 = "<IsVM>b_"
        $a4 = "<ParseDatWallets>b_"
        $a5 = "<ParseExtensions>b_"
        $a6 = "<ParseDiscordTokens>b_"
        $b1 = "Phemedrone.Senders"
        $b2 = "Phemedrone.Protections"
        $b3 = "Phemedrone.Extensions"
        $b4 = "Phemedrone.Cryptography"
        $b5 = "Phemedrone-Report.zip"
        $b6 = "Phemedrone Stealer Report"
    condition:
        all of ($a*) or all of ($b*)
}

