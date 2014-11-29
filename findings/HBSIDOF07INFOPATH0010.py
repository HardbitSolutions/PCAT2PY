
#!/usr/bin/python
################################################################################
# V17579
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
        return r"V-17579"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Control behavior when opening eMail forms in the Trusted Site Security Zone - InfoPath"

    def get_vulnerability_discussion(self):
        return r"When InfoPath solutions are opened locally, the location of the form is checked so that updates to the form can be downloaded. If a user saves a form locally from a location in the Trusted Sites zone and then opens the same form from another location in the Trusted Sites zone, the cache will be updated with the new location information. If the user then opens the first form from its saved location, there will be a mismatch between the locally saved form and the locally cached form. This situation would typically happen when developers move forms to a new location, but if there is no warning when the cached location is used it could be misused by an attacker attempting to redirect the forms to a new location. This type of attack is a form of beaconing.By default, if the location information in the cached form and the saved form do not match, then the form cannot be opened without prompting the user for consent. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Office InfoPath 2007 \ Security \ ?Control behavior when opening forms in the Trusted Site security zone? will be set to ?Enabled (Block)?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath\Open Behaviors', 'Trusted Site')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath\Open Behaviors', ('Trusted Site=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath\Open Behaviors'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\12.0\InfoPath\Open Behaviors' -name 'Trusted Site' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007InfoPath"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07InfoPath0010"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"