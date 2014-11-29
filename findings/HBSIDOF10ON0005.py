
#!/usr/bin/python
################################################################################
# V17184
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
        return r"V-17184"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Links that invoke instances of IE from within an Office product must be blocked."

    def get_vulnerability_discussion(self):
        return r"The Pop-up Blocker feature in Internet Explorer can be used to block most unwanted pop-up and pop-under windows from appearing. This functionality can be controlled separately for instances of Internet Explorer spawned by Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a Web page). If the Pop-up Blocker is disabled, disruptive and potentially dangerous pop-up windows could load and present a security risk. Set the policy value for: Computer Configuration \ Administrative Templates \ Microsoft Office 2010 (Machine) \ Security Settings \ IE Security ?Block popups? to ?Enabled? and select ?onent.exe''."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT', 'onenote.exe')

        # Output Lines
        self.__output = [r'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT', ('onenote.exe=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Internet Explorer\Main'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT' -name 'onenote.exe' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2010OneNote"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf10ON0005"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"