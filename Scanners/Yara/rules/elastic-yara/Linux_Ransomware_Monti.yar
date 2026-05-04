rule Linux_Ransomware_Monti_9c64f016 {
    meta:
        author = "Elastic Security"
        id = "9c64f016-0fd9-41bf-8916-cdf3a35efdd6"
        fingerprint = "af28cc97eed328f3b2b0181784545e41a521e9dfff09a504177cb56929606b84"
        creation_date = "2023-07-27"
        last_modified = "2024-02-13"
        threat_name = "Linux.Ransomware.Monti"
        reference_sample = "ad8d1b28405d9aebae6f42db1a09daec471bf342e9e0a10ab4e0a258a7fa8713"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a1 = "[%s] Flag doesn't equal MONTI."
        $a2 = "--vmkill Whether to kill the virtual machine"
        $a3 = "MONTI strain."
        $a4 = "http://monti"
    condition:
        2 of them
}

