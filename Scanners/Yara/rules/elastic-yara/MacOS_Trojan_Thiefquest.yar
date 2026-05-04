rule MacOS_Trojan_Thiefquest_9130c0f3 {
    meta:
        author = "Elastic Security"
        id = "9130c0f3-5926-4153-87d8-85a591eed929"
        fingerprint = "38916235c68a329eea6d41dbfba466367ecc9aad2b8ae324da682a9970ec4930"
        creation_date = "2021-09-30"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Thiefquest"
        reference_sample = "bed3561210e44c290cd410adadcdc58462816a03c15d20b5be45d227cd7dca6b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = "heck_if_targeted" ascii fullword
        $a2 = "check_command" ascii fullword
        $a3 = "askroot" ascii fullword
        $a4 = "iv_rescue_data" ascii fullword
    condition:
        all of them
}

rule MacOS_Trojan_Thiefquest_fc2e1271 {
    meta:
        author = "Elastic Security"
        id = "fc2e1271-3c96-4c93-9e3d-212782928e6e"
        fingerprint = "195e8f65e4ea722f0e1ba171f2ad4ded97d4bc97da38ef8ac8e54b8719e4c5ae"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Thiefquest"
        reference_sample = "12fb0eca3903a3b39ecc3c2aa6c04fe5faa1f43a3d271154d14731d1eb196923"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 30 30 30 42 67 7B 30 30 }
    condition:
        all of them
}

rule MacOS_Trojan_Thiefquest_86f9ef0c {
    meta:
        author = "Elastic Security"
        id = "86f9ef0c-832e-4e4a-bd39-c80c1d064dbe"
        fingerprint = "e8849628ee5449c461f1170c07b6d2ebf4f75d48136f26b52bee9bcf4e164d5b"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Thiefquest"
        reference_sample = "59fb018e338908eb69be72ab11837baebf8d96cdb289757f1f4977228e7640a0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 6C 65 31 6A 6F 57 4E 33 30 30 30 30 30 33 33 00 30 72 7A 41 43 47 33 57 72 7C }
    condition:
        all of them
}

rule MacOS_Trojan_Thiefquest_40f9c1c3 {
    meta:
        author = "Elastic Security"
        id = "40f9c1c3-29f8-4699-8f66-9b7ddb08f92d"
        fingerprint = "27ec200781541d5b1abc96ffbb54c428b773bffa0744551bbacd605c745b6657"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Thiefquest"
        reference_sample = "e402063ca317867de71e8e3189de67988e2be28d5d773bbaf75618202e80f9f6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 33 7C 49 56 7C 6A 30 30 }
    condition:
        all of them
}

rule MacOS_Trojan_Thiefquest_0f9fe37c {
    meta:
        author = "Elastic Security"
        id = "0f9fe37c-77df-4d3d-be8a-c62ea0f6863c"
        fingerprint = "2e809d95981f0ff813947f3be22ab3d3c000a0d348131d5d6c8522447818196d"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Thiefquest"
        reference_sample = "12fb0eca3903a3b39ecc3c2aa6c04fe5faa1f43a3d271154d14731d1eb196923"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 33 71 6B 6E 6C 55 30 55 }
    condition:
        all of them
}

rule MacOS_Trojan_Thiefquest_1f4bac78 {
    meta:
        author = "Elastic Security"
        id = "1f4bac78-ef2b-49cd-8852-e84d792f6e57"
        fingerprint = "e7d1e2009ff9b33d2d237068e2af41a8aa9bd44a446a2840c34955594f060120"
        creation_date = "2021-10-05"
        last_modified = "2021-10-25"
        threat_name = "MacOS.Trojan.Thiefquest"
        reference_sample = "12fb0eca3903a3b39ecc3c2aa6c04fe5faa1f43a3d271154d14731d1eb196923"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 32 33 4F 65 49 66 31 68 }
    condition:
        all of them
}

