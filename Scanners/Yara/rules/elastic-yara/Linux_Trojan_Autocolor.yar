rule Linux_Trojan_Autocolor_18203450 {
    meta:
        author = "Elastic Security"
        id = "18203450-339b-4f21-8f22-72fdc6fa02da"
        fingerprint = "0aa1c8156590617aa60e855be214c443ac9c0dc7633950b206fc8f2ab2d3d86a"
        creation_date = "2025-03-11"
        last_modified = "2025-03-19"
        threat_name = "Linux.Trojan.Autocolor"
        reference_sample = "a492f6d4183a8809c69e415be5d241f227f6b6a56e0ab43738fd36e435116aa0"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "auto-color"
        $str2 = "/var/log/cross"
        $str3 = "/tmp/cross"
        $str4 = "/proc/self/fd/%d"
        $str5 = "/www/wwwlogs/%s"
        $str6 = "/door-%d.log"
        $str7 = "/etc/ld.so.preload.real"
        $str8 = "ad.real"
        $str9 = "/tmp/config-err-"
    condition:
        5 of ($str*)
}

