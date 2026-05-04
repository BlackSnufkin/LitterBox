rule Windows_Trojan_DarkCloud_9905abce {
    meta:
        author = "Elastic Security"
        id = "9905abce-cbfc-4c92-aef6-38f2099eb5da"
        fingerprint = "5aeb210b37f4b2b4032917f53f2fb0422132aa1f8cddf0f47bccf50ff68ce00c"
        creation_date = "2023-05-03"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.DarkCloud"
        reference_sample = "500cb8459c19acd5a1144c4b509c14dbddec74ad623896bfe946fde1cd99a571"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 8D 45 DC 57 57 6A 01 6A 11 50 6A 01 68 80 00 00 00 89 7D E8 89 }
        $a2 = { C8 33 FF 50 57 FF D6 8D 4D DC 51 57 FF D6 C3 8B 4D F0 8B 45 }
    condition:
        all of them
}

