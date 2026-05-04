rule Windows_Trojan_Octopus_15813e26 {
    meta:
        author = "Elastic Security"
        id = "15813e26-77f8-46cf-a6a3-ae081925b85a"
        fingerprint = "a3294547f7e3cead0cd64eb3d2e7dbd8ccfc4d9eedede240a643c8cd114cbcce"
        creation_date = "2021-11-10"
        last_modified = "2022-01-13"
        description = "Identifies Octopus, an Open source pre-operation C2 server based on Python and PowerShell"
        threat_name = "Windows.Trojan.Octopus"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "C:\\Users\\UNKNOWN\\source\\repos\\OctopusUnmanagedExe\\OctopusUnmanagedExe\\obj\\x64\\Release\\SystemConfiguration.pdb" ascii fullword
    condition:
        all of them
}

