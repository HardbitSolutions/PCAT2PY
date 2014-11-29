
#!/usr/bin/python
################################################################################
# V41493
#
# Justin Dierking
# justindierking@hardbitsolutions.com
# phnomcobra@gmail.com
#
# Python implementation of PCAT by Hardbit Solutions:
# Generated MANUAL finding
#
# 09/30/2014 Original Construction
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
        return r"V-41493"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"Text in Outlook that represents Internet and network paths must not be automatically turned into hyperlinks."

    def get_vulnerability_discussion(self):
        return r"The ability of Outlook to automatically turn text that represents Internet and network paths into hyperlinks would allow users to click on those hyperlinks in email messages and access malicious or otherwise harmful websites. 1. From the main Outlook window, go to Tools > Options2. Click on the Mail Format tab > Editor Options3. In the left pane, navigate to and click on Proofing4. In the right pane, click on the AutoCorrect Option button5. Click on the AutoFormat tab''Internet and network path into hyperlinks'' checkbox must be unchecked."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "Office2010Outlook"

    def get_hippa(self):
        return ""
    
    def get_pci(self):
        return ""
    
    def get_hbs_id(self):
        return "HBSIDOf10OUT0084"
    
    def get_dod8500_2(self):
        return "ECSC-1"

    def get_800_53(self):
        return "CM-6"
    
    def get_iso_27001(self):
        return "A.10.10.2"