rule Windows_Trojan_P8Loader_e478a831 {
    meta:
        author = "Elastic Security"
        id = "e478a831-b2a1-4436-8b17-ca92b9581c39"
        fingerprint = "267743fc82c701d3029cde789eb471b49839001b21b90eeb20783382a56fb2c3"
        creation_date = "2023-04-13"
        last_modified = "2023-05-26"
        threat_name = "Windows.Trojan.P8Loader"
        reference = "https://www.elastic.co/security-labs/elastic-charms-spectralviper"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "\t[+] Create pipe direct std success\n" fullword
        $a2 = "\tPEAddress: %p\n" fullword
        $a3 = "\tPESize: %ld\n" fullword
        $a4 = "DynamicLoad(%s, %s) %d\n" fullword
        $a5 = "LoadLibraryA(%s) FAILED in %s function, line %d" fullword
        $a6 = "\t[+] No PE loaded on memory\n" wide fullword
        $a7 = "\t[+] PE argument: %ws\n" wide fullword
        $a8 = "LoadLibraryA(%s) FAILED in %s function, line %d" fullword
    condition:
        5 of them
}

