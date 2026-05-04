rule Linux_Downloader_Generic_0bd15ae0 {
    meta:
        author = "Elastic Security"
        id = "0bd15ae0-e4fe-48a9-84a6-f8447b467651"
        fingerprint = "67e14ea693baee8437157f6e450ac5e469b1bab7d9ff401493220575aae9bc91"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Downloader.Generic"
        reference_sample = "e511efb068e76a4a939c2ce2f2f0a089ef55ca56ee5f2ba922828d23e6181f09"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 89 D0 83 C0 01 EB 05 B8 FF FF FF FF 48 8B 5D E8 64 48 33 1C 25 28 00 }
    condition:
        all of them
}

