rule Linux_Rootkit_Perfctl_ce456896 {
    meta:
        author = "Elastic Security"
        id = "ce456896-1a13-4e31-8913-55f5b49badcb"
        fingerprint = "feda52cd93fa66194b030d5cb759ceef9b97073bb765349e8f06af6f37b547bc"
        creation_date = "2024-11-14"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Perfctl"
        reference_sample = "69de4c062eebb13bf2ee3ee0febfd4a621f2a17c3048416d897aecf14503213a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = { 48 01 D0 48 89 45 F0 48 8B 45 F0 48 89 C6 48 C7 C7 FF FF FF FF }
        $a2 = { BF 5E F8 00 00 E8 ?? ?? FF FF 66 89 85 52 FF FF FF BF 01 00 00 7F E8 ?? ?? FF FF 89 85 54 FF FF FF }
        $str1 = "r;rr" wide
        $str2 = { 0D 0A 25 73 0D 0A }
        $str3 = "rrr01" wide
    condition:
        any of ($a*) or 2 of ($str*)
}

