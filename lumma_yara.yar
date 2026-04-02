/*
 * YARA Rules for Lumma Stealer (LummaC2) Detection
 * Course: EECS 4484 – Malware Analysis
 * Sources: CISA AA25-141B, Netskope Threat Labs, CrowdStrike
 */

/*
 * Rule 1 — Lumma Stealer C2 Communication Pattern
 * Detects network traffic and binary strings associated with Lumma's
 * C2 communication: TeslaBrowser/5.5 user-agent and .shop TLD C2 domains.
 * References: CISA AA25-141B; ConnectWise CRU (Jan 2025)
 */
rule LummaStealer_C2_Comms
{
    meta:
        author       = "Group 15 Hoang Vu, Hieu Vu"
        description  = "Detects Lumma Stealer C2 communication artifacts"
        reference    = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-141b"
        date         = "2025-03"
        malware      = "LummaC2 / Lumma Stealer"
        tlp          = "WHITE"

    strings:
        $ua   = "TeslaBrowser/5.5"          ascii wide
        $tld1 = ".shop"                      ascii wide
        $tld2 = ".top"                       ascii wide
        $post = "/c2sock"                    ascii wide
        $cfg  = "lumma"                      ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and           // PE file (MZ header)
        $ua and
        ( $post or ( $tld1 and $tld2 ) ) and
        $cfg
}

/*
 * Rule 2 — Lumma Stealer AMSI Bypass & Execution Artifacts
 * Detects the in-memory AMSI bypass technique (clr.dll patching) and
 * process injection into RegSvcs.exe used by Lumma Stealer.
 * References: Netskope Threat Labs (Jan 2025); Cybereason GSOC (2024)
 */
rule LummaStealer_AMSI_Bypass
{
    meta:
        author      = "Group 15 Hoang Vu, Hieu Vu"
        description = "Detects Lumma Stealer AMSI bypass and LOLBin execution artifacts"
        reference   = "https://www.netskope.com/blog/lumma-stealer-fake-captchas-new-techniques-to-evade-detection"
        date        = "2025-03"
        malware     = "LummaC2 / Lumma Stealer"
        tlp         = "WHITE"

    strings:
        $amsi1  = "AmsiScanBuffer"          ascii wide
        $amsi2  = "clr.dll"                 ascii wide
        $lolbin = "mshta.exe"               ascii wide nocase
        $target = "RegSvcs.exe"             ascii wide nocase
        $ps1    = "Invoke-Expression"       ascii wide nocase
        $ps2    = "iex"                     ascii wide
        $b64    = /[A-Za-z0-9+\/]{80,}={0,2}/ ascii   // Base64 blob

    condition:
        uint16(0) == 0x5A4D and
        ( ($amsi1 and $amsi2) or ($lolbin and $target) ) and
        ($ps1 or $ps2) and
        $b64
}
