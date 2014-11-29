
#!/usr/bin/python
################################################################################
# V2374
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated DWORD EQ finding
#
# 09/21/2014 Original Construction
################################################################################

class Finding:
    # Initialize compliance
    def __init__(self):
        self.__verbose = False
        self.__output = []
        self.__is_compliant = []

    def get_verbose(self):
        return self.__verbose

    def get_output(self):
        return self.__output

    def get_severity(self):
        return "CAT I"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-2374"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The system is configured to autoplay removable media."

    def get_vulnerability_discussion(self):
        return r"Autoplay begins reading from a drive as soon as you insert media in the drive.  As a result, the setup file of programs and the music on audio media starts immediately.  By default, Autoplay is disabled on removable drives, such as the floppy disk drive (but not the CD-ROM drive), and on network drives.  If you enable this policy, you can also disable Autoplay on all drives. Set the policy value for Computer Configuration \ Administrative Templates \ System \ ?Turn off AutoPlay? to ?Enabled:All Drives?.Note:  This was previously configured in the checklist using the Security Option setting ?MSS: (NoDriveTypeAutorun) Disable Autorun on all drives? set to ?255, disable Autorun for all drives?.  This updates the same registry value (NoDriveTypeAutorun) as the Administrative Template setting.In addition to the above, Microsoft has released patches to correct issues with this setting.   The patches from either Microsoft?s KB953252 (patch KB950582) or KB967715 must be installed.  This will add the HonorAutorunSetting registry value."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer', 'NoDriveTypeAutorun')

        # Output Lines
        self.__output = [r'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer', ('NoDriveTypeAutorun=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 255:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion'")
        cli.powershell(r"New-Item -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies'")
        cli.powershell(r"New-Item -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer' -name 'NoDriveTypeAutorun' -value 255 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2003MS"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K3MS000087"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"