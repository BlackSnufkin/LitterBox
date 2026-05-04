rule MacOS_Backdoor_Useragent_1a02fc3a {
    meta:
        author = "Elastic Security"
        id = "1a02fc3a-a394-457b-8af5-99f7f22b0a3b"
        fingerprint = "22afa14a3dc6f8053b93bf3e971d57808a9cc19e676f9ed358ba5f1db9292ba4"
        creation_date = "2021-11-11"
        last_modified = "2022-07-22"
        threat_name = "MacOS.Backdoor.Useragent"
        reference_sample = "623f99cbe20af8b79cbfea7f485d47d3462d927153d24cac4745d7043c15619a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $s1 = "/Library/LaunchAgents/com.UserAgent.va.plist"
        $s2 = "this is not root"
        $s3 = "rm -Rf "
        $s4 = "/start.sh"
        $s5 = ".killchecker_"
    condition:
        4 of them
}

