rule Linux_Trojan_Pnscan_20e34e35 {
    meta:
        author = "Elastic Security"
        id = "20e34e35-8639-4a0d-bfe3-6bfa1570f14d"
        fingerprint = "07678bd23ae697d42e2c7337675f7a50034b10ec7a749a8802820904a943641a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Pnscan"
        reference_sample = "7dbd5b709f16296ba7dac66dc35b9c3373cf88452396d79d0c92d7502c1b0005"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4C 00 54 45 4C 20 3A 20 00 3C 49 41 43 3E 00 3C 44 4F 4E 54 3E 00 }
    condition:
        all of them
}

