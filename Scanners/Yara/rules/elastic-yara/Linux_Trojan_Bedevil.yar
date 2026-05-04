rule Linux_Trojan_Bedevil_a1a72c39 {
    meta:
        author = "Elastic Security"
        id = "a1a72c39-c8a3-4372-bd1d-de6360c9c19e"
        fingerprint = "ea4762d6ba0b88017feda1ed68d70bedd1438bb853b8ee1f83cbca2276bfbd1e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Bedevil"
        reference_sample = "017a9d7290cf327444d23227518ab612111ca148da7225e64a9f6ebd253449ab"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 73 3A 20 1B 5B 31 3B 33 31 6D 25 64 1B 5B 30 6D 0A 00 1B 5B }
    condition:
        all of them
}

