rule Windows_Ransomware_Ransomexx_fabff49c {
    meta:
        author = "Elastic Security"
        id = "fabff49c-8e1a-4020-b081-2f432532e529"
        fingerprint = "a7a1e6d5fafdddc7d4699710edf407653968ffd40747c50f26ef63a6cb623bbe"
        creation_date = "2021-08-07"
        last_modified = "2021-10-04"
        threat_name = "Windows.Ransomware.Ransomexx"
        reference_sample = "480af18104198ad3db1518501ee58f9c4aecd19dbbf2c5dd7694d1d87e9aeac7"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "ransom.exx" ascii fullword
        $a2 = "Infrastructure rebuild will cost you MUCH more." wide fullword
        $a3 = "Your files are securely ENCRYPTED." wide fullword
        $a4 = "delete catalog -quiet" wide fullword
    condition:
        all of them
}

