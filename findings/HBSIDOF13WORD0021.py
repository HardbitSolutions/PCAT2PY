
#!/usr/bin/python
################################################################################
# V26592
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
        return r"V-26592"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Configuration for file validation must be enforced."

    def get_vulnerability_discussion(self):
        return r"Office File Validation helps detect and prevent a kind of exploit known as a file format attack or file fuzzing attack. File format attacks exploit the integrity of a file. They occur when someone modifies the structure of a file with the intent of adding malicious code. Usually the malicious code is run remotely and is used to elevate the privilege of restricted accounts on the computer. As a result, an attacker could gain access to a computer that they did not previously have access to. This could enable an attacker to read sensitive information from the computer''s hard disk drive or install malware, such as a worm or a key logging program. The Office File Validation feature helps prevent file format attacks by scanning and validating files before they are opened. To validate files, Office File Validation compares a file''s structure to a predefined file schema, which is a set of rules that determine what a readable file looks like. If Office File Validation detects that a file''s structure does not follow all rules that are described in the schema, the file does not pass validation. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft Word 2013 \ Word Options \ Security ''Turn off file validation'' to ''Disabled''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\15.0\word\security\filevalidation', 'EnableOnLoad')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\15.0\word\security\filevalidation', ('EnableOnLoad=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\word'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\word\security'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\word\security\filevalidation'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\15.0\word\security\filevalidation' -name 'EnableOnLoad' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013Word"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Word0021"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"