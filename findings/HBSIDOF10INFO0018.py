
#!/usr/bin/python
################################################################################
# V17764
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
        return r"V-17764"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Unsafe file types must be prevented from being attached to InfoPath forms."

    def get_vulnerability_discussion(self):
        return r"Users can attach any type of file to forms except potentially unsafe files that might contain viruses, such as .bat or .exe files. For the full list of file types that InfoPath disallows by default, see ''Security Details'' in Insert a file attachment control on the Microsoft Office Online Web site.If unsafe file types are added to InfoPath forms, they might be used as a means of attacking the computer on which the form is opened. These unsafe file types may include active content, or may introduce other vulnerabilities that an attacker can exploit. Set the policy value for: User Configuration \ Administrative Templates \ Microsoft InfoPath 2010 \ Security \ ?Prevent users from allowing unsafe file types to be attached to forms? to ?Enabled?."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKCU:\Software\Policies\Microsoft\Office\14.0\infopath\security', 'DisallowAttachmentCustomization')

        # Output Lines
        self.__output = [r'HKCU:\Software\Policies\Microsoft\Office\14.0\infopath\security', ('DisallowAttachmentCustomization=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\infopath'")
        cli.powershell(r"New-Item -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\infopath\security'")
        cli.powershell(r"Set-ItemProperty -path 'HKCU:\Software\Policies\Microsoft\Office\14.0\infopath\security' -name 'DisallowAttachmentCustomization' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2010InfoPath"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf10Info0018"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"