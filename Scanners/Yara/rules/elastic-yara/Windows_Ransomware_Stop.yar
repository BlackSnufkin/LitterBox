rule Windows_Ransomware_Stop_1e8d48ff {
    meta:
        author = "Elastic Security"
        id = "1e8d48ff-e0ab-478d-8268-a11f2e87ab79"
        fingerprint = "bef9770e8deb4a5ba76cea1050ca0de1ef9ab6a6aa53f071126c3f0dacf368fd"
        creation_date = "2021-06-10"
        last_modified = "2025-09-26"
        threat_name = "Windows.Ransomware.Stop"
        reference_sample = "821b27488f296e15542b13ac162db4a354cbf4386b6cd40a550c4a71f4d628f3"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "E:\\Doc\\My work (C++)\\_Git\\Encryption\\Release\\encrypt_win_api.pdb" ascii fullword
        $b = { 68 FF FF FF 50 FF D3 8D 85 78 FF FF FF 50 FF D3 8D 85 58 FF FF FF C6 45 FC 01 50 FF D3 85 F6 79 36 56 68 }
    condition:
        any of them
}

