
#!/usr/bin/python
################################################################################
# V36679
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
        return r"V-36679"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Early Launch Antimalware, Boot-Start Driver Initialization Policy must be enabled and configured to only Good and Unknown."

    def get_vulnerability_discussion(self):
        return r"Compromised boot drivers can introduce malware prior to some protection mechanisms that load after initialization.  The Early Launch Antimalware driver can limit allowed drivers based on classifications determined by the malware protection application.  At a minimum, drivers determined to be bad must not be allowed. Set the policy value for Computer Configuration \ Administrative Templates \ System \ Early Launch Antimalware \ ''Boot-Start Driver Initialization Policy'' to ''Enabled'' with ''Good and Unknown'' selected."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Policies\EarlyLaunch', 'DriverLoadPolicy')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Policies\EarlyLaunch', ('DriverLoadPolicy=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Policies'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Policies\EarlyLaunch'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Policies\EarlyLaunch' -name 'DriverLoadPolicy' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Win8"

    def get_hippa(self):
        return "164.308(a)(5)(ii)(B)"
    
    def get_pci(self):
        return "5.1, 5.2"
    
    def get_hbs_id(self):
        return "HBSPCATWIN8000310"
    
    def get_dod8500_2(self):
        return "ECVP-1"

    def get_800_53(self):
        return "SI-3"
    
    def get_iso_27001(self):
        return "A.10.4.1, A.10.9.3"