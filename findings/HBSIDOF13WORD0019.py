
#!/usr/bin/python
################################################################################
# V26588
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
        return r"V-26588"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Scripted Window Security must be enforced."

    def get_vulnerability_discussion(self):
        return r"Malicious websites often try to confuse or trick users into giving a site permission to perform an action allowing the site to take control of the users'' computers in some manner. Disabling or not configuring this setting allows unknown websites to:-Create browser windows appearing to be from the local operating system.-Draw active windows displaying outside of the viewable areas of the screen capturing keyboard input.-Overlay parent windows with their own browser windows to hide important system information, choices or prompts. Set the policy value for: Computer Configuration \ Administrative Templates \ Microsoft Office 2013 (Machine) \ Security Settings \ IE Security ''Scripted Window Security Restrictions'' to ''Enabled'' and ''winword.exe'' is checked."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS', 'winword.exe')

        # Output Lines
        self.__output = [r'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS', ('winword.exe=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Internet Explorer\Main'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS' -name 'winword.exe' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2013Word"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf13Word0019"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"