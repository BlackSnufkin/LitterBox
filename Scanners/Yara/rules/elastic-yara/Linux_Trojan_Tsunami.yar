rule Linux_Trojan_Tsunami_d9e6b88e {
    meta:
        author = "Elastic Security"
        id = "d9e6b88e-256c-4e9d-a411-60b477b70446"
        fingerprint = "8fc61c0754d1a8b44cefaf2dbd937ffa0bb177d98b071347d2f9022181555b7a"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "a4ac275275e7be694a200fe6c5c5746256398c109cf54f45220637fe5d9e26ba"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 04 02 01 20 03 20 02 C9 07 40 4E 00 60 01 C0 04 17 B6 92 07 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_30c039e2 {
    meta:
        author = "Elastic Security"
        id = "30c039e2-1c51-4309-9165-e3f2ce79cd6e"
        fingerprint = "4c97fed719ecfc68e7d67268f19aff545447b4447a69814470fe676d4178c0ed"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "b494ca3b7bae2ab9a5197b81e928baae5b8eac77dfdc7fe1223fee8f27024772"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 E0 0F B6 00 84 C0 74 1F 48 8B 45 E0 48 8D 50 01 48 8B 45 E8 48 83 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_c94eec37 {
    meta:
        author = "Elastic Security"
        id = "c94eec37-8ae1-48d2-8c75-36f2582a2742"
        fingerprint = "c692073af446327f739e1c81f4e3b56d812c00c556e882fe77bfdff522082db4"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "294fcdd57fc0a53e2d63b620e85fa65c00942db2163921719d052d341aa2dc30"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 05 88 10 8B 45 E4 0F B6 10 83 E2 0F 83 CA 40 88 10 8B 45 E4 C6 40 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_f806d5d9 {
    meta:
        author = "Elastic Security"
        id = "f806d5d9-0bf6-4da7-80fb-b1612f2ddd5b"
        fingerprint = "f4f838fcd1fe7f85e435225f3e34b77b848246b2b9618b47125a611c8d282347"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "5259495788f730a2a3bad7478c1873c8a6296506a778f18bc68e39ce48b979da"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 41 54 45 48 54 54 50 20 3C 68 6F 73 74 3E 20 3C 73 72 63 3A }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_0fa3a6e9 {
    meta:
        author = "Elastic Security"
        id = "0fa3a6e9-89f3-4bc8-8dc1-e9ccbeeb836d"
        fingerprint = "fed796c5275e2e91c75dcdbf73d0c0ab37591115989312c6f6c5adcd138bc91f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "40a15a186373a062bfb476b37a73c61e1ba84e5fa57282a7f9ec0481860f372a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { EC 8B 55 EC C1 FA 10 0F B7 45 EC 01 C2 89 55 EC 8B 45 EC C1 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_36a98405 {
    meta:
        author = "Elastic Security"
        id = "36a98405-8b95-49cb-98c5-df4a445d9d39"
        fingerprint = "c76ca23eece4c2d4ec6656ffb40d6e6ea7777d8a904f4775913fe60ebd606cd6"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "a57de6cd3468f55b4bfded5f1eed610fdb2cbffbb584660ae000c20663d5b304"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 05 88 85 50 FF FF FF 0F B6 85 50 FF FF FF 83 E0 0F 83 C8 40 88 85 50 FF }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_0c6686b8 {
    meta:
        author = "Elastic Security"
        id = "0c6686b8-8880-4a2c-ba70-9a9840a618b0"
        fingerprint = "7bab1c0cf4fb79c50369f991373178ef3b5d3f7afd765dac06e86ac0c27e0c83"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "409c55110d392aed1a9ec98a6598fb8da86ab415534c8754aa48e3949e7c4b62"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 F8 31 C0 48 8B 45 C8 0F B7 40 02 66 89 45 D0 48 8B 45 C8 8B }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_9ce5b69f {
    meta:
        author = "Elastic Security"
        id = "9ce5b69f-4938-4576-89da-8dcd492708ed"
        fingerprint = "90fece6c2950467d78c8a9f1d72054adf854f19cdb33e71db0234a7b0aebef47"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "ad63fbd15b7de4da0db1b38609b7481253c100e3028c19831a5d5c1926351829"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F4 8B 54 85 B4 8B 45 E4 8D 04 02 C6 00 00 FF 45 F4 8B 45 E4 01 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_55a80ab6 {
    meta:
        author = "Elastic Security"
        id = "55a80ab6-3de4-48e1-a9de-28dc3edaa104"
        fingerprint = "2fe3a9e1115d8c2269fe090c57ee3d5b2cd52b4ba1d020cec0135e2f8bbcb50e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "5259495788f730a2a3bad7478c1873c8a6296506a778f18bc68e39ce48b979da"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 74 68 65 20 63 75 72 72 65 6E 74 20 73 70 6F 6F 66 69 6E 67 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_e98b83ee {
    meta:
        author = "Elastic Security"
        id = "e98b83ee-0533-481a-9947-538bd2f99b6b"
        fingerprint = "b5440c783bc18e23f27a3131ccce4629f8d0ceea031971cbcdb69370ab52e935"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "cf1ca1d824c8687e87a5b0275a0e39fa101442b4bbf470859ddda9982f9b3417"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 45 FE 00 00 EB 16 48 8B 55 D8 0F B7 02 0F B7 C0 01 45 E0 48 83 45 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_8a11f9be {
    meta:
        author = "Elastic Security"
        id = "8a11f9be-dc85-4695-9f38-80ca0304780e"
        fingerprint = "91e2572a3bb8583e20042578e95e1746501c6a71ef7635af2c982a05b18d7c6d"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "1f773d0e00d40eecde9e3ab80438698923a2620036c2fc33315ef95229e98571"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 3E 20 3C 70 6F 72 74 3E 20 3C 72 65 66 6C 65 63 74 69 6F 6E 20 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_2462067e {
    meta:
        author = "Elastic Security"
        id = "2462067e-06cf-409c-8184-86bd7a772690"
        fingerprint = "f84d62ad2d6f907a47ea9ff565619648564b7003003dc8f20e28a582a8331e6b"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "3847f1c7c15ce771613079419de3d5e8adc07208e1fefa23f7dd416b532853a1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 8B 45 F4 8B 40 0C 89 C1 8B 45 F4 8B 40 10 8B 10 8D 45 E4 89 C7 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_0a028640 {
    meta:
        author = "Elastic Security"
        id = "0a028640-581f-4183-9313-e36c5812e217"
        fingerprint = "1b296e8baffbe3e0e49aee23632afbfab75147f31561d73eb0c82f909c5ec718"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "e36081f0dbd6d523c9378cdd312e117642b0359b545b29a61d8f9027d8c0f2f0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 10 85 C0 74 2D 8B 45 0C 0F B6 00 84 C0 74 19 8B 45 0C 83 C0 01 83 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_47f93be2 {
    meta:
        author = "Elastic Security"
        id = "47f93be2-687c-42d2-9627-29f114beb234"
        fingerprint = "f4a2262cfa0f0db37e15149cf33e639fd2cd6d58f4b89efe7860f73014b47c4e"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "2e4f89c76dfefd4b2bfd1cf0467ac0324026355723950d12d7ed51195fd998cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { FA 48 63 C6 48 89 94 C5 70 FF FF FF 8B 85 5C FF FF FF 8D 78 01 48 8D 95 60 FF }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_6b3974b2 {
    meta:
        author = "Elastic Security"
        id = "6b3974b2-fd7f-4ebf-8aba-217761e7b846"
        fingerprint = "942a35f7acacf1d07577fe159a34dc7b04e5d07ff32ea13be975cfeea23e34be"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "2216776ba5c6495d86a13f6a3ce61b655b72a328ca05b3678d1abb7a20829d04"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { F4 89 45 EC 8B 45 EC C9 C3 55 89 E5 57 83 EC 0C EB 1F 8B 45 08 B9 FF FF }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_87bcb848 {
    meta:
        author = "Elastic Security"
        id = "87bcb848-cd8b-478c-87de-5df8c457024c"
        fingerprint = "ffd1a95ba4801bb51ce9b688bdb9787d4a8e3bc3a60ad0f52073f5c531bc6df7"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "575b0dc887d132aa3983e5712b8f642b03762b0685fbd5a32c104bca72871857"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 65 6D 6F 74 65 00 52 65 6D 6F 74 65 20 49 52 43 20 42 6F 74 00 23 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_ad60d7e8 {
    meta:
        author = "Elastic Security"
        id = "ad60d7e8-0823-4bfa-b823-681c554bf297"
        fingerprint = "e1ca4c566307238a5d8cd16db8d0d528626e0b92379177b167ce25b4c88d10ce"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 4E 4F 54 49 43 45 20 25 73 20 3A 53 70 6F 6F 66 73 3A 20 25 64 2E 25 64 2E 25 64 2E 25 64 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_22646c0d {
    meta:
        author = "Elastic Security"
        id = "22646c0d-785c-4cf2-b8c8-289189ae14d0"
        fingerprint = "0b1dce4e74536d4d06430aefd0127c740574dcc9a0e5ada42f3d51d97437720f"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "20439a8fc21a94c194888725fbbb7a7fbeef5faf4b0f704559d89f1cd2e57d9d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { CB 01 00 00 55 53 51 52 48 01 FE 56 48 89 FE 48 89 D7 31 DB }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_019f0e75 {
    meta:
        author = "Elastic Security"
        id = "019f0e75-a766-4778-8337-c5bce478ecd9"
        fingerprint = "3b66dcdd89ce564cf81689ace33ee91682972421a9926efa1985118cefebdddc"
        creation_date = "2021-01-12"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "575b0dc887d132aa3983e5712b8f642b03762b0685fbd5a32c104bca72871857"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 2E 0A 00 2B 73 74 64 00 2B 73 74 6F 70 00 2B 75 6E 6B 6E 6F }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_7c545abf {
    meta:
        author = "Elastic Security"
        id = "7c545abf-822d-44bb-8ac9-1b7e4f27698d"
        fingerprint = "4141069d6c41c0c26b53a8a86fd675f09982ca6e99757a04ef95b9ad0b8efefa"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "95691c7ad1d80f7f1b5541e1d1a1dbeba30a26702a4080d256f14edb75851c5d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 03 FC DF 40 9C B8 20 07 09 20 35 15 11 03 20 85 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_32c0b950 {
    meta:
        author = "Elastic Security"
        id = "32c0b950-0636-42bb-bc67-1b727985625f"
        fingerprint = "e438287517c3492fa87115a3aa5402fd05f9745b7aed8e251fb3ed9d653984bb"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "214c1caf20ceae579476d3bf97f489484df4c5f1c0c44d37ff9b9066072cd83c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 05 20 BC F8 41 B8 20 07 09 20 35 15 11 03 20 85 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_cbf50d9c {
    meta:
        author = "Elastic Security"
        id = "cbf50d9c-2893-48c9-a2a9-45053f0a174b"
        fingerprint = "acb32177d07df40112d99ed0a2b7ed01fbca63df1f63387cf939caa4cf1cf83b"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "b64d0cf4fc4149aa4f63900e61b6739e154d328ea1eb31f4c231016679fc4aa5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 07 F8 BF 81 9C B8 20 07 09 20 35 15 11 03 20 85 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_40c25a06 {
    meta:
        author = "Elastic Security"
        id = "40c25a06-5f3c-42c1-9a8c-5c4a1568ff9a"
        fingerprint = "b45d666e2e7d571e95806a1a2c8e01cd5cd0d71160cbb06b268110d459ee252d"
        creation_date = "2021-04-06"
        last_modified = "2021-09-16"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "61af6bb7be25465e7d469953763be5671f33c197d4b005e4a78227da11ae91e9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 74 13 9C B8 20 07 09 20 35 15 11 03 20 85 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_35806adc {
    meta:
        author = "Elastic Security"
        id = "35806adc-9bac-4481-80c8-a673730d5179"
        fingerprint = "f0b4686087ddda1070b62ade7ad7eb69d712e15f5645aaba24c0f5b124a283ac"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "15e7942ebf88a51346d3a5975bb1c2d87996799e6255db9e92aed798d279b36b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 85 3C 93 48 1F 03 36 84 C0 4B 28 7F 18 86 13 08 10 1F EC B0 73 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_d74d7f0c {
    meta:
        author = "Elastic Security"
        id = "d74d7f0c-70f8-4dd7-aaf4-fd5ab94bb8b2"
        fingerprint = "0a175d0ff64186d35b64277381f47dfafe559a42a3296a162a951f1b2add1344"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "b0a8b2259c00d563aa387d7e1a1f1527405da19bf4741053f5822071699795e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 20 79 6F 2C 0A 59 6A 02 5B 6A 04 58 CD 80 B3 7F 6A 01 58 CD }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_71d31510 {
    meta:
        author = "Elastic Security"
        id = "71d31510-cd2c-4b61-b2cf-975d5ed70c93"
        fingerprint = "6c9f3f31e9dcdcd4b414e79e06f0ae633e50ef3e19a437c1b964b40cc74a57cb"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "33dd6c0af99455a0ca3908c0117e16a513b39fabbf9c52ba24c7b09226ad8626"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 5C B3 C0 19 17 5E 7B 8B 22 16 17 E0 DE 6E 21 46 FB DD 17 67 }
    condition:
        all of them
}

rule Linux_Trojan_Tsunami_97288af8 {
    meta:
        author = "Elastic Security"
        id = "97288af8-f447-48ba-9df3-4e90f1420249"
        fingerprint = "a1e20b699822b47359c8585ff01da06f585b9d7187a433fe0151394b16aa8113"
        creation_date = "2021-12-13"
        last_modified = "2022-01-26"
        threat_name = "Linux.Trojan.Tsunami"
        reference_sample = "c39eb055c5f71ebfd6881ff04e876f49495c0be5560687586fc47bf5faee0c84"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $a = { 61 6E 64 65 6D 6F 20 73 68 69 72 61 6E 61 69 20 77 61 20 79 6F 2C }
    condition:
        all of them
}

