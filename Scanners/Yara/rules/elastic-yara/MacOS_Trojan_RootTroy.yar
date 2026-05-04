rule MacOS_Trojan_RootTroy_d77adb36 {
    meta:
        author = "Elastic Security"
        id = "d77adb36-c435-449b-94f0-ed6e16964f25"
        fingerprint = "7e3ea46336e6225a1a879e18a57055b7b4396f3d30601012d5c30e2be3331fad"
        creation_date = "2026-02-24"
        last_modified = "2026-04-06"
        threat_name = "MacOS.Trojan.RootTroy"
        reference_sample = "ad01beb19f5b8c7155ee5415781761d4c7d85a31bb90b618c3f5d9f737f2d320"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "Documents/Dev/root-troy-v4/main.go" ascii fullword
        $a2 = "Documents/Dev/root-troy-v4/cryptoutil/rand.go" ascii fullword
        $a3 = "rtv4/osutil.execScript" ascii fullword
        $a4 = "rtv4/osutil.LoggedInUsers" ascii fullword
        $a5 = "rtv4/cryptoutil.RandomString" ascii fullword
        $a6 = "main.logoutMonitor" ascii fullword
        $a7 = "main.getConfigPath" ascii fullword
    condition:
        4 of them
}

