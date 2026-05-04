rule Windows_Trojan_Babylonrat_0f66e73b {
    meta:
        author = "Elastic Security"
        id = "0f66e73b-7824-46b6-a9e6-5abf018c9ffa"
        fingerprint = "3998824e381f51aaa2c81c12d4c05157c642d8aef39982e35fa3e124191640ea"
        creation_date = "2021-09-02"
        last_modified = "2022-01-13"
        threat_name = "Windows.Trojan.Babylonrat"
        reference_sample = "4278064ec50f87bb0471053c068b13955ed9d599434e687a64bf2060438a7511"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "BabylonRAT" wide fullword
        $a2 = "Babylon RAT Client" wide fullword
        $a3 = "ping 0 & del \"" wide fullword
        $a4 = "\\%Y %m %d - %I %M %p" wide fullword
    condition:
        all of them
}

