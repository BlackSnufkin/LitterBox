rule Windows_Ransomware_Conti_89f3f6fa {
    meta:
        author = "Elastic Security"
        id = "89f3f6fa-492c-40e3-a4aa-a526004197b2"
        fingerprint = "a82331eba3cbd52deb4bed5e11035ac1e519ec27931507f582f2985865c0fb1a"
        creation_date = "2021-08-05"
        last_modified = "2021-10-04"
        threat_name = "Windows.Ransomware.Conti"
        reference_sample = "eae876886f19ba384f55778634a35a1d975414e83f22f6111e3e792f706301fe"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { F7 FE 88 57 FF 83 EB 01 75 DA 8B 45 FC 5F 5B 40 5E 8B E5 5D C3 8D }
    condition:
        all of them
}

