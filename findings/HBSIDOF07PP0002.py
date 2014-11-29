
#!/usr/bin/python
################################################################################
# V17173
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
        return r"V-17173"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Disable user name and password syntax from being used in URLs"

    def get_vulnerability_discussion(self):
        return r"The Uniform Resource Locator (URL) standard allows user authentication to be included in URL strings in the form http://username:password@example.com. A malicious user might use this URL syntax to create a hyperlink that appears to open a legitimate Web site but actually opens a deceptive (spoofed) Web site. For example, the URL http://www.wingtiptoys.com@example.com appears to open http://www.wingtiptoys.com but actually opens http://example.com. To protect users from such attacks, Internet Explorer usually blocks any URLs using this syntax.This functionality can be controlled separately for instances of Internet Explorer spawned by 2007 Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a Web page). If user names and passwords in URLs are allowed, users could be diverted to dangerous Web pages, which could pose a security risk. Set the policy value for: Computer Configuration \ Administrative Templates \ Microsoft Office 2007 system (Machine) \ Security Settings \ IE Security ?Disable user name and password? will be set to ?Enabled? and ?powerpnt.exe? and ?pptview.exe? are checked.Note: In Office SP2 adm use, filtering in GPEDIT.MSC should have deselected any checks in ''Only show configured policy settings'' box, and ''Only show policy settings that can be fully managed'' box, in order to view the hive within the GP Console for policy use."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def check(self, cli):
        # Initialize Compliance
        self.__is_compliant = False

        # Get Registry DWORD
        dword = cli.get_reg_dword(r'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE', 'powerpnt.exe')

        # Output Lines
        self.__output = [r'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE', ('powerpnt.exe=' + str(dword))]

        if self.__verbose:
            print self.__output

        if dword == 1:
            self.__is_compliant = True

        return self.__is_compliant

    def fix(self, cli):
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Internet Explorer\Main'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl'")
        cli.powershell(r"New-Item -path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE'")
        cli.powershell(r"Set-ItemProperty -path 'HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE' -name 'powerpnt.exe' -value 1 -Type DWord")

    def get_compliance(self):
        return self.__is_compliant

    def get_posture(self):
        return "Office2007PowerPoint"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf07PP0002"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"