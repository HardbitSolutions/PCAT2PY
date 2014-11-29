
#!/usr/bin/python
################################################################################
# V2373
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
        return r"V-2373"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"The Server Operators group must have the ability to schedule jobs by means of the AT command disabled."

    def get_vulnerability_discussion(self):
        return r"This policy controls the ability of members of the local Server Operators group to schedule AT jobs. If disabled, only administrators can schedule jobs that use AT commands. Unlike Scheduled Tasks which require you to specify the credential under which the task will run, AT jobs run under the authority of whatever account the AT service runs (SYSTEM by default). Non administrators who can schedule AT commands, thus have a means to elevate their privileges.  Although this setting is disabled, Server Operators will still be able to schedule jobs using Task Scheduler. Set the value for ?Domain Controller: Allow server operators to schedule tasks? to ?Disabled?.The policy referenced configures the following registry value:Registry Hive: HKEY_LOCAL_MACHINE Registry Path: \System\CurrentControlSet\Control\LSA\Value Name:  SubmitControlValue Type:  REG_DWORDValue:  0"

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\System\CurrentControlSet\Control\LSA\Value', 'SubmitControl')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Control\LSA\Value', ('SubmitControl=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control\LSA'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control\LSA\Value'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\LSA\Value' -name 'SubmitControl' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2008R2DC"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT2K8R2DC0000188"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"