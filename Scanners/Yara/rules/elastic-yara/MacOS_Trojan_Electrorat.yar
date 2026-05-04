rule MacOS_Trojan_Electrorat_b4dbfd1d {
    meta:
        author = "Elastic Security"
        id = "b4dbfd1d-4968-4121-a4c2-5935b7f76fc1"
        fingerprint = "fa65fc0a8f5b1f63957c586e6ca8e8fbdb811970f25a378a4ff6edf5e5c44da7"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Electrorat"
        reference_sample = "b1028b38fcce0d54f2013c89a9c0605ccb316c36c27faf3a35adf435837025a4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "_TtC9Keylogger9Keylogger" ascii fullword
        $a2 = "_TtC9Keylogger17CallBackFunctions" ascii fullword
        $a3 = "\\DELETE-FORWARD" ascii fullword
        $a4 = "\\CAPSLOCK" ascii fullword
    condition:
        all of them
}

