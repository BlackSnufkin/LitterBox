rule Multi_Trojan_SparkRat_9a21e541 {
    meta:
        author = "Elastic Security"
        id = "9a21e541-886c-4d7f-8602-832862121730"
        fingerprint = "2691da3a037b651d0f7f6d7be767c34845c3b9a642f4a2fb1c54f391f08089b6"
        creation_date = "2023-11-13"
        last_modified = "2024-06-12"
        threat_name = "Multi.Trojan.SparkRat"
        reference_sample = "23efecc03506a9428175546a4b7d40c8a943c252110e83dec132c6a5db8c4dd6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "Spark/client/service/file" ascii wide
        $a2 = "Spark/client/service/desktop" ascii wide
        $a3 = "Spark/utils.Encrypt" ascii wide
    condition:
        all of them
}

