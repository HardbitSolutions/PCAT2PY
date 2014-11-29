
#!/usr/bin/python
################################################################################
# V3481
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
        return "CAT II"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-3481"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Media Player will be configured to prevent automatic Codec downloads."

    def get_vulnerability_discussion(self):
        return r"The Windows Media Player uses software components, referred to as Codecs, to play back media files.  By default, when an unknown file type is opened with the Media Player it will search the Internet for the appropriate Codec and automatically download it.  To ensure platform consistency and to protect against new vulnerabilities associated with media types, all Codecs must be installed by the System Administrator. Set the policy value for User Configuration \ Administrative Templates \ Windows Components \ Windows Media Player \ Playback ?Prevent Codec Download? to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer', 'PreventCodecDownload')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer', ('PreventCodecDownload=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer' -name 'PreventCodecDownload' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008R2MS"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2MS0000306"
    
    def get_dod8500_2(self):
        return "DCSL-1"

    def get_800_53(self):
        return "CM-5(6)"
    
    def get_iso_27001(self):
        return "A.10.1.2, A.12.4.1, A.12.4.3, A.12.5.3"