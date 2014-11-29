
#!/usr/bin/python
################################################################################
# V4445
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# 
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated MULTISZ EQ finding
#
# 09/23/2014 Original Construction
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
        return r"V-4445"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Optional Subsystems must not be permitted to operate on the system."

    def get_vulnerability_discussion(self):
        return r"The POSIX subsystem is an Institute of Electrical and Electronic Engineers (IEEE) standard that defines a set of operating system services.  The POSIX Subsystem is required if the server supports applications that use that subsystem.  The subsystem introduces a security risk relating to processes that can potentially persist across logins.  That is, if a user starts a process and then logs out, there is a potential that the next user who logs in to the system could access the previous users process.  This is dangerous because the process started by the first user may retain that users system privileges, and anything the second user does with that process will be performed with the privileges of the first user. Set the policy value for Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options \ ''System settings: Optional subsystems'' to ''Blank'' (Configured with no entries)."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        multi_sz = cli.get_reg_multi_sz(r'HKLM:\System\CurrentControlSet\Control\Session Manager\Subsystems', 'Optional')

        # Output Lines
        self.__output = [r'HKLM:\System\CurrentControlSet\Control\Session Manager\Subsystems', ('Optional=')] + multi_sz

        if self.__verbose:
            print self.__output

        if multi_sz == ['']:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control\Session Manager'")
        cli.powershell(r"New-Item -path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Subsystems'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Subsystems' -name 'Optional' -Type MultiString -value $null")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "2012MS"

    def get_hippa(self):
        return "164.312( c)(1)"
    
    def get_pci(self):
        return "2.2.4"
    
    def get_hbs_id(self):
        return "HBSPCAT12MS0000403"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"