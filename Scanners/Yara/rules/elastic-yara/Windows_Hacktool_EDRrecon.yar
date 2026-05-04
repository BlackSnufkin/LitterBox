rule Windows_Hacktool_EDRrecon_69453aff {
    meta:
        author = "Elastic Security"
        id = "69453aff-1427-4aae-b1f3-7cce9c93342c"
        fingerprint = "f10758ed032a0f7da0d983839beb12f79fba764aa4ffa0f3716dbfc2e8a3ea82"
        creation_date = "2024-03-07"
        last_modified = "2024-06-10"
        threat_name = "Windows.Hacktool.EDRrecon"
        reference_sample = "f62e51b2405c0d42c53ff1f560376ef0530ba2eea1c97e18f2a3cf148346bcd1"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s01 = "WdFilter.sys" ascii wide fullword
        $s02 = "mpFilter.sys" ascii wide fullword
        $s03 = "SRTSP.sys" ascii wide fullword
        $s04 = "eeCtrl.sys" ascii wide fullword
        $s05 = "360AvFlt.sys" ascii wide fullword
        $s06 = "360fsflt.sys" ascii wide fullword
        $s07 = "esensor.sys" ascii wide fullword
        $s09 = "klflt.sys" ascii wide fullword
        $s10 = "klam.sys" ascii wide fullword
        $s11 = "SysmonDrv.sys" ascii wide fullword
        $s12 = "CarbonBlackK.sys" ascii wide fullword
        $s13 = "edrsensor.sys" ascii wide fullword
        $s14 = "naswSP.sys" ascii wide fullword
        $s15 = "symevnt.sys" ascii wide fullword
        $s16 = "symevnt32.sys" ascii wide fullword
        $s17 = "CyProtectDrv" ascii wide fullword
        $s18 = "mfeaskm.sys" ascii wide fullword
        $s19 = "SentinelMonitor.sys" ascii wide fullword
        $s20 = "sentinelelam.sys" ascii wide fullword
        $s21 = "SophosSupport.sys" ascii wide fullword
        $s22 = "CSDeviceControl.sys" ascii wide fullword
        $s23 = "csagent.sys" ascii wide fullword
        $s24 = "avgntflt.sys" ascii wide fullword
        $s25 = "bddevflt.sys" ascii wide fullword
        $s26 = "CiscoAMPHeurDriver.sys" ascii wide fullword
        $s27 = "DeepInsFS.sys" ascii wide fullword
        $s28 = "eamonm.sys" ascii wide fullword
        $s29 = "fortirmon.sys" ascii wide fullword
        $s30 = "FlightRecorder.sys" ascii wide fullword
        $s31 = "TmKmSnsr.sys" ascii wide fullword
        $s32 = "cpepmon.sys" ascii wide fullword
        $s33 = "cposfw.sys" ascii wide fullword
        $s34 = "cyvrmtgn.sys" ascii wide fullword
        $s35 = "elastic-endpoint-driver.sys" ascii wide fullword
        $s36 = "elasticelam.sys" ascii wide fullword
        $37 = "mbamwatchdog.sys" ascii wide fullword
        $38 = "FortiEDRWinDriver" ascii wide fullword
        $39 = "QaxNfDrv.sys" ascii wide fullword
        $40 = "qmnetmonw64.sys" ascii wide fullword
        $s41 = "TFsFlt.sys" ascii wide fullword
        $s42 = "DsArk64.sys" ascii wide fullword
    condition:
        14 of them
}

rule Windows_Hacktool_EDRrecon_ca314aa1 {
    meta:
        author = "Elastic Security"
        id = "ca314aa1-3bbe-489c-a77a-fb7a0eca1f67"
        fingerprint = "58c6c2cbb92262098af27f8434863d1ea91c31f02727c5dde72d6ac07b3b872d"
        creation_date = "2024-03-07"
        last_modified = "2024-06-10"
        threat_name = "Windows.Hacktool.EDRrecon"
        reference_sample = "f62e51b2405c0d42c53ff1f560376ef0530ba2eea1c97e18f2a3cf148346bcd1"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s01 = "SentinelAgent.exe" ascii wide fullword
        $s02 = "SentinelUI.exe" ascii wide fullword
        $s03 = "MsMpEng.exe" ascii wide fullword
        $s04 = "SenseIR.exe" ascii wide fullword
        $s05 = "elastic-endpoint.exe" ascii wide fullword
        $s06 = "elastic-agent.exe" ascii wide fullword
        $s07 = "CylanceSvc.exe" ascii wide fullword
        $s09 = "CybereasonAV.exe" ascii wide fullword
        $s10 = "Traps.exe" ascii wide fullword
        $s11 = "CyvrFsFlt.exe" ascii wide fullword
        $s12 = "EIConnector.exe" ascii wide fullword
        $s13 = "ekrn.exe" ascii wide fullword
        $s14 = "fortiedr.exe" ascii wide fullword
        $s15 = "RepMgr.exe" ascii wide fullword
        $s16 = "TaniumDetectEngine.exe" ascii wide fullword
        $s17 = "CSFalconService.exe" ascii wide fullword
        $s18 = "CSFalconContainer.exe" ascii wide fullword
        $s19 = "EndpointBasecamp.exe" ascii wide fullword
        $s20 = "hmpalert.exe" ascii wide fullword
        $s21 = "xagt.exe" ascii wide fullword
        $s22 = "TMBMSRV.exe" ascii wide fullword
        $s23 = "EIConnector.exe" ascii wide fullword
        $s25 = "mcsclient.exe" ascii wide fullword
        $s26 = "sophososquery.exe" ascii wide fullword
        $s27 = "TaniumClient.exe" ascii wide fullword
        $s28 = "asdsvc.exe" ascii wide fullword
        $s29 = "avp.exe" ascii wide fullword
        $s30 = "avpui.exe" ascii wide fullword
        $s31 = "mbae-svc.exe" ascii wide fullword
        $s32 = "mbae.exe" ascii wide fullword
        $s33 = "ccSvcHst.exe" ascii wide fullword
        $s35 = "bdagent.exe" ascii wide fullword
        $s36 = "ir_agent.exe" ascii wide fullword
        $s37 = "eguiproxy.exe" ascii wide fullword
        $s38 = "ekrn.exe" ascii wide fullword
        $s39 = "Sysmon64.exe" ascii wide fullword
        $s40 = "Sysmon.exe" ascii wide fullword
    condition:
        14 of them
}

