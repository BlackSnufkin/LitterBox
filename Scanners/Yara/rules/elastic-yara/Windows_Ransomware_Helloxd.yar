rule Windows_Ransomware_Helloxd_0c50f01b {
    meta:
        author = "Elastic Security"
        id = "0c50f01b-5f3d-4112-9930-ca1150fc12fa"
        fingerprint = "462d8c231d608e28e66d810b811f9fdf82d0b3770d21267a4375669a26bbaafd"
        creation_date = "2022-06-14"
        last_modified = "2022-07-18"
        threat_name = "Windows.Ransomware.Helloxd"
        reference_sample = "435781ab608ff908123d9f4758132fa45d459956755d27027a52b8c9e61f9589"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $mutex = "With best wishes And good intentions..."
        $ransomnote0 = ":: our TOX below >:)"
        $ransomnote1 = "You can download TOX here"
        $ransomnote2 = "...!XD ::"
        $productname = "HelloXD" ascii wide
        $legalcopyright = "uKn0w" ascii wide
        $description = "VhlamAV" ascii wide
        $companyname = "MicloZ0ft" ascii wide
    condition:
        ($mutex and all of ($ransomnote*)) or (3 of ($productname, $legalcopyright, $description, $companyname))
}

