
#!/usr/bin/python
################################################################################
# V6309
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
        return r"V-6309"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Clipboard operations via script must be disallowed (Restricted Sites zone)."

    def get_vulnerability_discussion(self):
        return r"A malicious script could use the clipboard in an undesirable manner, for example, if the user had recently copied confidential information to the clipboard while editing a document, a malicious script could harvest that information.  It might be possible to exploit other vulnerabilities in order to send the harvested data to the attacker.  Allow paste operations via script must have level of protection based upon the site being accessed. Manipulate the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> ?Allow cut, copy or paste operations from the clipboard via script? to ?Enabled? and select ?Disable? from the drop-down box."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4', '1407')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4', ('1407=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 3:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4' -name '1407' -value 3 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE9"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE9000036"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"