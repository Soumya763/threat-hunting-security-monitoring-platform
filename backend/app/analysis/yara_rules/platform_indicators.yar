/*
 * Indicator rules written for this platform. They are triage hints built from
 * public, well-known patterns; they are NOT signatures of specific malware
 * families. Each rule's severity feeds the risk score.
 */

rule eicar_test_file {
    meta:
        severity = "low"
        description = "Standard antivirus test string (EICAR). Harmless, used to test detection."
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
    condition:
        $eicar
}

rule encoded_powershell_command {
    meta:
        severity = "high"
        description = "PowerShell encoded-command option, often used to hide a payload."
    strings:
        $ps = "powershell" nocase ascii wide
        $enc = /-e(nc|ncodedcommand)?\s/ nocase ascii wide
    condition:
        $ps and $enc
}

rule office_shell_automation {
    meta:
        severity = "medium"
        description = "Office or script content that creates a shell object."
    strings:
        $shell = "WScript.Shell" nocase ascii wide
        $create = "CreateObject" nocase ascii wide
    condition:
        $shell and $create
}

rule download_and_execute_api {
    meta:
        severity = "high"
        description = "Imports or strings for downloading a file and launching it."
    strings:
        $dl = "URLDownloadToFile" nocase ascii wide
        $run = "WinExec" nocase ascii wide
    condition:
        all of them
}

rule pdf_auto_javascript {
    meta:
        severity = "high"
        description = "PDF with JavaScript and an automatic open action."
    strings:
        $pdf = "%PDF-" ascii
        $js = "/JavaScript" ascii
        $open = "/OpenAction" ascii
    condition:
        $pdf at 0 and $js and $open
}

rule double_extension_name {
    meta:
        severity = "high"
        description = "File or archive entry name pretends to be a document but ends in an executable extension."
    strings:
        $a = ".pdf.exe" nocase ascii wide
        $b = ".doc.exe" nocase ascii wide
        $c = ".docx.exe" nocase ascii wide
        $d = ".xls.scr" nocase ascii wide
        $e = ".pdf.scr" nocase ascii wide
    condition:
        any of them
}

rule autorun_inf_launcher {
    meta:
        severity = "medium"
        description = "autorun.inf file that launches a program from removable media."
    strings:
        $a = "[autorun]" nocase ascii
        $b = /open\s*=/ nocase ascii
    condition:
        $a and $b
}
