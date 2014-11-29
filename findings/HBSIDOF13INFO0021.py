
#!/usr/bin/python
################################################################################
# V26620
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
        return r"V-26620"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Disabling opening forms with managed code from the Internet security zone must be configured."

    def get_vulnerability_discussion(self):
        return r"When InfoPath solutions are opened locally, the location of the form is checked so that updates to the form can be downloaded. If a user saves a form locally from a location on the Internet and then opens the same form from another location on the Internet, the cache will be updated with the new location information. If the user then opens the first form from its saved location, there will be a mismatch between the locally saved form and the locally cached form. This situation would typically happen when developers move forms to a new location, but if there is no warning when the cached location is used, it could be misused by an attacker attempting to redirect the forms to a new location. This type of attack is a form of beaconing. By default, if the location information in the cached form and the saved form to not match, the form cannot be opened without prompting the user for consent. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft InfoPath 2013 \ Security ''Disable opening forms with managed code from the Internet security zone'' to ''Enabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\15.0\InfoPath\security', 'RunManagedCodeFromInternet')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\InfoPath\security', ('RunManagedCodeFromInternet=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\InfoPath'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\InfoPath\security'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\InfoPath\security' -name 'RunManagedCodeFromInternet' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013InfoPath"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Info0021"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"