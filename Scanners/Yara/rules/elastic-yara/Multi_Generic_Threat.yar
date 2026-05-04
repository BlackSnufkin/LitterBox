rule Multi_Generic_Threat_19854dc2 {
    meta:
        author = "Elastic Security"
        id = "19854dc2-a568-4f6c-bd47-bcae9976c66f"
        fingerprint = "64d3803490fa71f720678ca2989cc698ea9b1a398d02d6d671fa01e0ff42f8b5"
        creation_date = "2024-02-21"
        last_modified = "2024-06-12"
        threat_name = "Multi.Generic.Threat"
        reference_sample = "be216fa9cbf0b64d769d1e8ecddcfc3319c7ca8e610e438dcdfefc491730d208"
        severity = 50
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = { 26 2A 73 74 72 75 63 74 20 7B 20 45 6E 74 72 79 53 61 6C 74 20 5B 5D 75 69 6E 74 38 3B 20 4C 65 6E 20 69 6E 74 20 7D }
    condition:
        all of them
}

