
#!/usr/bin/python
################################################################################
# V17603
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
        return r"V-17603"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Prompts to convert older databases must be enforced."

    def get_vulnerability_discussion(self):
        return r"When users open databases that were created in the Access 97 file format, Access 2013 prompts them to convert the database to a newer file format.  Users can choose to convert the database or leave it in the older format.  Disabling this setting ensures Access 2013 prompts the user, and is therefore unlikely to cause usability issues. Otherwise, if Access 2013 was allowed to automatically convert the database, it may be converting outdated code which is not compatible or tested with the newer version. In addition, if the database is used by multiple users, there is the potential of making the database inaccessible to other users who may not be using Access 2013. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Access 2013 \ Miscellaneous ''Do not prompt to convert older databases'' to ''Disabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\15.0\access\settings', 'NoConvertDialog')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\access\settings', ('NoConvertDialog=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 0:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\access'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\access\settings'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\access\settings' -name 'NoConvertDialog' -value 0 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013Access"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Access0009"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"