rule MacOS_Backdoor_Fakeflashlxk_06fd8071 {
    meta:
        author = "Elastic Security"
        id = "06fd8071-0370-4ae8-819a-846fa0a79b3d"
        fingerprint = "a0e6763428616b46536c6a4eb080bae0cc58ef27678616aa432eb43a3d9c77a1"
        creation_date = "2021-11-11"
        last_modified = "2022-07-22"
        threat_name = "MacOS.Backdoor.Fakeflashlxk"
        reference_sample = "107f844f19e638866d8249e6f735daf650168a48a322d39e39d5e36cfc1c8659"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $s1 = "/Users/lxk/Library/Developer/Xcode/DerivedData"
        $s2 = "Desktop/SafariFlashActivity/SafariFlashActivity/SafariFlashActivity/"
        $s3 = "/Debug/SafariFlashActivity.build/Objects-normal/x86_64/AppDelegate.o"
    condition:
        2 of them
}

