rule Windows_Trojan_AveMaria_31d2bce9 {
    meta:
        author = "Elastic Security"
        id = "31d2bce9-3266-447b-9a2d-57cf11a0ff1f"
        fingerprint = "8f75e2d8308227a42743168deb021de18ad485763fd257991c5e627c025c30c0"
        creation_date = "2021-05-30"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.AveMaria"
        reference_sample = "5767bca39fa46d32a6cb69ef7bd1feaac949874768dac192dbf1cf43336b3d7b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q " ascii fullword
        $a2 = "SMTP Password" wide fullword
        $a3 = "select signon_realm, origin_url, username_value, password_value from logins" ascii fullword
        $a4 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" wide fullword
        $a5 = "for /F \"usebackq tokens=*\" %%A in (\"" wide fullword
        $a6 = "\\Torch\\User Data\\Default\\Login Data" wide fullword
        $a7 = "/n:%temp%\\ellocnak.xml" wide fullword
        $a8 = "\"os_crypt\":{\"encrypted_key\":\"" wide fullword
        $a9 = "Hey I'm Admin" wide fullword
        $a10 = "\\logins.json" wide fullword
        $a11 = "Accounts\\Account.rec0" ascii fullword
        $a12 = "warzone160" ascii fullword
        $a13 = "Ave_Maria Stealer OpenSource github Link: https://github.com/syohex/java-simple-mine-sweeper" wide fullword
    condition:
        8 of ($a*)
}

rule Windows_Trojan_AveMaria_e01305a0 {
    meta:
        author = "Elastic Security"
        id = "e01305a0-724e-420a-99af-38a3c6436095"
        fingerprint = "52acf71c9a53a56337722c43d9bba34957815b8c2c6fe52bea9b38e343dae803"
        creation_date = "2025-08-18"
        last_modified = "2025-09-19"
        threat_name = "Windows.Trojan.AveMaria"
        reference_sample = "21f1e24abcda47e08ba3e6bf19c0b2d9adb52b908f625c4a08f74ade5b863bf9"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "SOFTWARE\\_rptls" wide fullword
        $b = "-w %ws -d C -f %s" fullword
        $c = "RDPClip" wide fullword
        $d = "ExplorerIdentifier" wide fullword
        $e = "WM_FIND" wide fullword
        $f = "WM_DISP" wide fullword
        $g = "MsgBox.exe" wide fullword
        $h = "Hey I'm Admin" wide fullword
        $i = "/n:%temp%\\ellocnak.xml" wide fullword
        $j = "CommandHandler::handleStartVncCommand() Start VNC on port : %d" wide fullword
    condition:
        7 of them
}

