rule Windows_Hacktool_SharPersist_06606812 {
    meta:
        author = "Elastic Security"
        id = "06606812-2be2-4155-a82b-6ab4629c5b5a"
        fingerprint = "44fd3f1146d81c34051f8ef4619db369d364e809799e7ca57bea93fb8fef5d4c"
        creation_date = "2022-10-20"
        last_modified = "2022-11-24"
        threat_name = "Windows.Hacktool.Sharpersist"
        reference_sample = "e9711f47cf9171f79bf34b342279f6fd9275c8ae65f3eb2c6ebb0b8432ea14f8"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $guid = "9D1B853E-58F1-4BA5-AEFC-5C221CA30E48" ascii wide nocase
        $print_str0 = "schtaskbackdoor: backdoor scheduled task" ascii wide
        $print_str1 = "schtaskbackdoor -m list -n <schtask name>" ascii wide
        $print_str2 = "SharPersist" ascii wide
        $print_str3 = "[+] SUCCESS: Keepass persistence backdoor added" ascii wide
    condition:
        $guid or all of ($print_str*)
}

