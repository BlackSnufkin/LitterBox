rule MacOS_Backdoor_Kagent_64ca1865 {
    meta:
        author = "Elastic Security"
        id = "64ca1865-0a99-49dc-b138-02b17ed47f60"
        fingerprint = "b8086b08a019a733bee38cebdc4e25cdae9d3c238cfe7b341d8f0cd4db204d27"
        creation_date = "2021-11-11"
        last_modified = "2022-07-22"
        threat_name = "MacOS.Backdoor.Kagent"
        reference_sample = "d599d7814adbab0f1442f5a10074e00f3a776ce183ea924abcd6154f0d068bb4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $s1 = "save saveCaptureInfo"
        $s2 = "savephoto success screenCaptureInfo"
        $s3 = "no auto bbbbbaaend:%d path %s"
        $s4 = "../screencapture/screen_capture_thread.cpp"
        $s5 = "%s:%d, m_autoScreenCaptureQueue: %x"
        $s6 = "auto bbbbbaaend:%d path %s"
        $s7 = "auto aaaaaaaastartTime:%d path %s"
    condition:
        4 of them
}

