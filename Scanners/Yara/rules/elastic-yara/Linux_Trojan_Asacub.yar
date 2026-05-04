rule Linux_Trojan_Asacub_d3c4aa41 {
    meta:
        author = "Elastic Security"
        id = "d3c4aa41-faae-4c85-bdc5-9e09483e92fb"
        fingerprint = "4961023c719599bd8da6b8a17dbe409911334c21b45d62385dd02a6dd35fd2be"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Asacub"
        reference_sample = "15044273a506f825859e287689a57c6249b01bb0a848f113c946056163b7e5f1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 8B 0F 83 EC 08 50 57 FF 51 54 83 C4 10 8B 8B DC FF FF FF 89 4C }
    condition:
        all of them
}

