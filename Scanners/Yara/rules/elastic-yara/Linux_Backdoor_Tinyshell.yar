rule Linux_Backdoor_Tinyshell_67ee6fae {
    meta:
        author = "Elastic Security"
        id = "67ee6fae-304b-47f5-93b6-4086a864d433"
        fingerprint = "f71ce364fb607ee6f4422864674ae3d053453b488c139679aa485466893c563d"
        creation_date = "2021-10-12"
        last_modified = "2022-01-26"
        threat_name = "Linux.Backdoor.Tinyshell"
        reference_sample = "9d2e25ec0208a55fba97ac70b23d3d3753e9b906b4546d1b14d8c92f8d8eb03d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "Usage: %s [ -c [ connect_back_host ] ] [ -s secret ] [ -p port ]" fullword
        $a2 = "s:p:c::" fullword
        $b1 = "Usage: %s [ -s secret ] [ -p port ] [command]" fullword
        $b2 = "<hostname|cb> get <source-file> <dest-dir>" fullword
    condition:
        (all of ($a*)) or (all of ($b*))
}

