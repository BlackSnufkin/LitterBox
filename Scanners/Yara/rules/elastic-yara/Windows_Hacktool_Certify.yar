rule Windows_Hacktool_Certify_ffe1cca2 {
    meta:
        author = "Elastic Security"
        id = "ffe1cca2-106c-4197-9d26-eb90331435d9"
        fingerprint = "b5f40c2d70d3bde02561a275a4fff6033dce9e82964dc82144c040327877221b"
        creation_date = "2024-03-27"
        last_modified = "2025-12-18"
        threat_name = "Windows.Hacktool.Certify"
        reference_sample = "3c7f759a6c38d0c0780fba2d43be6dcf9e4869d54b66f16c0703ec8e58124953"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "<DisplayNtAuthCertificates>b_"
        $a2 = "<PrintAllowPermissions>b_"
        $a3 = "<ShowVulnerableTemplates>b_"
        $a4 = "<ParseCertificateApplicationPolicies>b_"
        $a5 = "<PrintCertTemplate>b_"
        $b1 = "64524ca5-e4d0-41b3-acc3-3bdbefd40c97" ascii wide
        $b2 = "64524CA5-E4D0-41B3-ACC3-3BDBEFD40C97" ascii wide
        $b3 = "Certify.exe find /vulnerable" wide
        $b4 = "Certify.exe request /ca" wide
    condition:
        all of ($a*) or 2 of ($b*)
}

