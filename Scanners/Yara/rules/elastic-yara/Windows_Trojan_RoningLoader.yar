rule Windows_Trojan_RoningLoader_a4e851ac {
    meta:
        author = "Elastic Security"
        id = "a4e851ac-7787-4f75-9aab-32c17c253c7a"
        fingerprint = "42d19ba97783f3807c096c1d1d5d17052530cc734d680c5baa8fc3c50cc10eee"
        creation_date = "2025-10-20"
        last_modified = "2025-11-03"
        threat_name = "Windows.Trojan.RoningLoader"
        reference_sample = "c84764a19543e9bdfe06263d3dd68bbf9df381bbe4d0c0da480bc4eddea293b6"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $binary0 = { 48 89 45 80 8B 05 C5 E8 0C 00 48 0F 47 4C 24 70 66 89 04 51 48 8D 44 24 70 66 44 89 6C 51 02 }
        $str0 = "Successfully created PPL process with PID: " wide fullword
        $str1 = "C:\\Windows\\System32\\ClipUp.exe" wide fullword
        $str2 = "regsvr32.exe /S"
    condition:
        $binary0 or all of ($str*)
}

