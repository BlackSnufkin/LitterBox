rule Windows_Trojan_Zeus_e51c60d7 {
    meta:
        author = "Elastic Security"
        id = "e51c60d7-3afa-4cf5-91d8-7782e5026e46"
        fingerprint = "813e2ee2447fcffdde6519dc6c52369a5d06c668b76c63bb8b65809805ecefba"
        creation_date = "2021-02-07"
        last_modified = "2021-10-04"
        description = "Detects strings used in Zeus web injects. Many other malware families are built on Zeus and may hit on this signature."
        threat_name = "Windows.Trojan.Zeus"
        reference = "https://www.virusbulletin.com/virusbulletin/2014/10/paper-evolution-webinjects"
        reference_sample = "d7e9cb60674e0a05ad17eb96f8796d9f23844a33f83aba5e207b81979d0f2bf3"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "name=%s&port=%u" ascii fullword
        $a2 = "data_inject" ascii wide fullword
        $a3 = "keylog.txt" ascii fullword
        $a4 = "User-agent: %s]]]" ascii fullword
        $a5 = "%s\\%02d.bmp" ascii fullword
    condition:
        all of them
}

