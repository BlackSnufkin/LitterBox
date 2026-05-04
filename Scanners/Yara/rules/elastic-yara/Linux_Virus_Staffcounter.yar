rule Linux_Virus_Staffcounter_d2d608a8 {
    meta:
        author = "Elastic Security"
        id = "d2d608a8-2d65-4b10-be71-0a0a6a027920"
        fingerprint = "a791024dc3064ed2e485e5c57d7ab77fc1ec14665c9302b8b572ac4d9d5d2f93"
        creation_date = "2021-06-28"
        last_modified = "2021-09-16"
        threat_name = "Linux.Virus.Staffcounter"
        reference = "06e562b54b7ee2ffee229c2410c9e2c42090e77f6211ce4b9fa26459ff310315"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 22 00 20 4C 69 6E 75 78 22 20 3C 00 54 6F 3A 20 22 00 20 }
    condition:
        all of them
}

