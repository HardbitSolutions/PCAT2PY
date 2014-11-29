
#!/usr/bin/python
################################################################################
# V41493
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
        return r"V-41493"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Text in Outlook that represents Internet and network paths must not be automatically turned into hyperlinks."

    def get_vulnerability_discussion(self):
        return r"The ability of Outlook to automatically turn text that represents Internet and network paths into hyperlinks would allow users to click on those hyperlinks in email message and access malicious or otherwise harmful websites. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Outlook 2013 \ Outlook Options \ ''Internet and network path into hyperlinks'' must be set to ''Disabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\software\policies\Microsoft\office\15.0\outlook\options\autoformat', 'pgrfafo_25_1')

        # Output Lines
        self.__output = [r'HKCU:\software\policies\Microsoft\office\15.0\outlook\options\autoformat', ('pgrfafo_25_1=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\outlook'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\outlook\options'")
        cli.powershell(r"New-Item -path 'HKCU:\software\policies\Microsoft\office\15.0\outlook\options\autoformat'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\software\policies\Microsoft\office\15.0\outlook\options\autoformat' -name 'pgrfafo_25_1' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013Outlook"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Out0082"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"