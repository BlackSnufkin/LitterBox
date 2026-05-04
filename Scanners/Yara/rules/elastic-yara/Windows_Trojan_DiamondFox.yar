rule Windows_Trojan_DiamondFox_18bc11e3 {
    meta:
        author = "Elastic Security"
        id = "18bc11e3-5872-40b0-a3b7-cef4b32fac15"
        fingerprint = "6f908d11220e218a7b59239ff3cc00c7e273fb46ec99ef7ae37e4aceb4de7831"
        creation_date = "2022-03-02"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.DiamondFox"
        reference_sample = "a44c46d4b9cf1254aaabd1e689f84c4d2c3dd213597f827acabface03a1ae6d1"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "\\wscript.vbs" wide fullword
        $a2 = "\\snapshot.jpg" wide fullword
        $a3 = "&soft=" wide fullword
        $a4 = "ping -n 4 127.0.0.1 > nul" wide fullword
        $a5 = "Select Name from Win32_Process Where Name = '" wide fullword
    condition:
        all of them
}

