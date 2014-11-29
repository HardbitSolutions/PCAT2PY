
#!/usr/bin/python
################################################################################
# V21967
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
        return "CAT III"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-21967"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Microsoft Support Diagnostic Tool (MSDT) interactive communication with Microsoft will be prevented."

    def get_vulnerability_discussion(self):
        return r"This setting prevents the MSDT from communicating with and sending collected data to Microsoft, the default support provider. Set the policy value for Computer Configuration \ Administrative Templates \ System \ Troubleshooting and Diagnostics \ Microsoft Support Diagnostic Tool \ ?Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with Support Provider? to ?Disabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy', 'DisableQueryRemoteServer')

        # Output Lines
        self.__output = [r'HKLM:\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy', ('DisableQueryRemoteServer=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy' -name 'DisableQueryRemoteServer' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008R2DC"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2DC0000177"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"