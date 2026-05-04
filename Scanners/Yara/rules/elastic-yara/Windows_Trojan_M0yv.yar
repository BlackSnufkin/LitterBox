rule Windows_Trojan_M0yv_92f66467 {
    meta:
        author = "Elastic Security"
        id = "92f66467-89fd-4501-b045-3c6aed6c82f9"
        fingerprint = "2afebc9478fbad18b74748794773cae9be3a4eac599d657bab5a7f8de331ba41"
        creation_date = "2023-05-03"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.M0yv"
        reference_sample = "0004d22dd18c0239b722c085101c0a32b967159e2066a0b7b9104bb43f5cdea0"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 54 65 7D 41 69 6E 63 5D 6A 68 6D }
        $a2 = { 4E 73 4D 62 62 77 61 6E 66 77 58 72 61 72 64 6C 7D }
        $a3 = { 40 65 7D 41 69 6E 63 48 77 71 7A 69 66 74 75 67 7A 55 }
    condition:
        all of them
}

