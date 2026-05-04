rule Windows_Trojan_Raccoon_af6decc6 {
    meta:
        author = "Elastic Security"
        id = "af6decc6-f917-4a80-b96d-1e69b8f8ebe0"
        fingerprint = "f9314a583040e4238aab7712ac16d7638a3b7c9194cbcf2ea9b4516c228c546b"
        creation_date = "2021-06-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Raccoon"
        reference_sample = "fe09bef10b21f085e9ca411e24e0602392ab5044b7268eaa95fb88790f1a124d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "A:\\_Work\\rc-build-v1-exe\\json.hpp" wide fullword
        $a2 = "\\stealler\\json.hpp" wide fullword
    condition:
        any of them
}

rule Windows_Trojan_Raccoon_58091f64 {
    meta:
        author = "Elastic Security"
        id = "58091f64-2118-47f8-bcb2-407a3c62fa33"
        fingerprint = "ea819b46ec08ba6b33aa19dcd6b5ad27d107a8e37f3f9eb9ff751fe8e1612f88"
        creation_date = "2021-06-28"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Raccoon"
        reference_sample = "fe09bef10b21f085e9ca411e24e0602392ab5044b7268eaa95fb88790f1a124d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 74 FF FF FF 10 8D 4D AC 53 6A 01 8D 85 60 FF FF FF 0F 43 85 60 FF }
    condition:
        all of them
}

rule Windows_Trojan_Raccoon_deb6325c {
    meta:
        author = "Elastic Security"
        id = "deb6325c-5556-44ce-a184-6369105485d5"
        fingerprint = "17c34b5b9a0211255a93f9662857361680e72a45135d6ea9b5af8d77b54583b9"
        creation_date = "2022-06-28"
        last_modified = "2022-07-18"
        threat_name = "Windows.Trojan.Raccoon"
        reference_sample = "f7b1aaae018d5287444990606fc43a0f2deb4ac0c7b2712cc28331781d43ae27"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "\\ffcookies.txt" wide fullword
        $a2 = "wallet.dat" wide fullword
        $a3 = "0Network\\Cookies" wide fullword
        $a4 = "Wn0nlDEXjIzjLlkEHYxNvTAXHXRteWg0ieGKVyD52CvONbW7G91RvQDwSZi/N2ISm4xEWRKYJwjnYUGS9OZmj/TAie8jG07EXEcO8D7h2m2lGzWnFG31R1rsxG1+G8E="
    condition:
        all of them
}

