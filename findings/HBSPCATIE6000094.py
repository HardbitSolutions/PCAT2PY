
#!/usr/bin/python
################################################################################
# V3432
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
        return r"V-3432"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Internet Explorer is configured to automatically check for updates."

    def get_vulnerability_discussion(self):
        return r"This setting determines whether or not Internet Explorer will periodically check the Microsoft web sites to determine if there are updates to Internet Explorer available.  The SA should manually install all updates on a system so that configuration control is maintained. Manipulate thepolicy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer ?Disable Periodic Check for Internet Explorer Software Updates? to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Internet Explorer\InfoDelivery\Restrictions', 'NoUpdateCheck')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Internet Explorer\InfoDelivery\Restrictions', ('NoUpdateCheck=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\InfoDelivery'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\InfoDelivery\Restrictions'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Internet Explorer\InfoDelivery\Restrictions' -name 'NoUpdateCheck' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "IE6"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSPCATIE6000094"
    
    def get_dod8500_2(self):
        return "DCSL-1"

    def get_800_53(self):
        return "CM-5(6)"
    
    def get_iso_27001(self):
        return "A.10.1.2, A.12.4.1, A.12.4.3, A.12.5.3"