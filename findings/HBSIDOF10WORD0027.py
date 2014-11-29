
#!/usr/bin/python
################################################################################
# V26616
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
        return r"V-26616"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Document behavior if file validation fails must be set."

    def get_vulnerability_discussion(self):
        return r"This policy key controls the behavior of how Office documents should be handled when failing File Validation. The options available are:-Block files completely. This will prevent users from opening files.-Open files in Protected View and disallow edit. This will prevent users from editing the files.-Open files in Protected view and allow edit. This will allow users to edit the files.If disabling or not configuring this policy setting, the default setting will be, ''open files in protected view and allow edit''. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Word 2010 \ Word Options \ Security \ Trust Center \ Protected View ?Set document behavior if file validation fails? to ''Enabled: Open in Protected View'' and Unchecked for ''Do not allow edit''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\14.0\word\security\filevalidation', 'OpenInProtectedView')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\14.0\word\security\filevalidation', ('OpenInProtectedView=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\word'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\word\security'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\word\security\filevalidation'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\word\security\filevalidation' -name 'OpenInProtectedView' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2010Word"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf10Word0027"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"