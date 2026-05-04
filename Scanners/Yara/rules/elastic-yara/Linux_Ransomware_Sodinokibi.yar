rule Linux_Ransomware_Sodinokibi_2883d7cd {
    meta:
        author = "Elastic Security"
        id = "2883d7cd-fd3b-47a5-9283-a40335172c62"
        fingerprint = "d6570a8e9358cef95388a72b2e7f747ee5092620c4f92a4b4e6c1bb277e1cb36"
        creation_date = "2022-01-05"
        last_modified = "2022-01-26"
        threat_name = "Linux.Ransomware.Sodinokibi"
        reference_sample = "a322b230a3451fd11dcfe72af4da1df07183d6aaf1ab9e062f0e6b14cf6d23cd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 85 08 FF FF FF 48 01 85 28 FF FF FF 48 8B 85 08 FF FF FF 48 29 85 20 FF }
    condition:
        all of them
}

