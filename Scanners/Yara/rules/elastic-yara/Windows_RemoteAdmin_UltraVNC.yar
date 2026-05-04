rule Windows_RemoteAdmin_UltraVNC_965f054a {
    meta:
        author = "Elastic Security"
        id = "965f054a-4b78-43f3-87db-1ecd64c317a0"
        fingerprint = "7e612ffb9fdf94471f938039b4077d5546edd5d6f700733e1c1e732aef36ed42"
        creation_date = "2023-03-18"
        last_modified = "2023-04-23"
        threat_name = "Windows.RemoteAdmin.UltraVNC"
        reference_sample = "59bddb5ccdc1c37c838c8a3d96a865a28c75b5807415fd931eaff0af931d1820"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s1 = ".\\vncsockconnect.cpp"
        $s2 = ".\\vnchttpconnect.cpp"
        $s3 = ".\\vncdesktopthread.cpp"
        $s4 = "Software\\UltraVNC"
        $s5 = "VncCanvas.class"
        $s6 = "WinVNC_Win32_Instance_Mutex"
        $s7 = "WinVNC.AddClient"
    condition:
        5 of them
}

