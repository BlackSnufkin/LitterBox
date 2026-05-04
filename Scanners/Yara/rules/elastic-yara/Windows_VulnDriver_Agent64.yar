rule Windows_VulnDriver_Agent64_8ef48aeb {
    meta:
        author = "Elastic Security"
        id = "8ef48aeb-56b2-408b-aaf1-b130d7eb1cf4"
        fingerprint = "3eab3bb33b75aec13d91d503a768001fc0da09a41c792904e4a5eab568b4f6f4"
        creation_date = "2022-07-19"
        last_modified = "2022-07-19"
        description = "Subject: eSupport.com, Inc OR Phoenix Technologies Ltd, Name: Agent64.sys, Version: 6.0"
        threat_name = "Windows.VulnDriver.Agent64"
        reference_sample = "05f052c64d192cf69a462a5ec16dda0d43ca5d0245900c9fcb9201685a2e7748"
        reference_sample = "4045ae77859b1dbf13972451972eaaf6f3c97bea423e9e78f1c2f14330cd47ca"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name_1 = { 06 03 55 04 03 [2] 50 68 6F 65 6E 69 78 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 4C 74 64 }
        $subject_name_2 = { 06 03 55 04 03 [2] 65 53 75 70 70 6F 72 74 2E 63 6F 6D 2C 20 49 6E 63 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 [1-8] 41 00 67 00 65 00 6E 00 74 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $product_version = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E [1-8] 36 00 2E 00 30 }
        $product_name = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 [1-8] 44 00 72 00 69 00 76 00 65 00 72 00 41 00 67 00 65 00 6E 00 74 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and any of ($subject_name*) and $original_file_name and $product_version and $product_name
}

