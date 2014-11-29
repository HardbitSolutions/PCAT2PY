
#!/usr/bin/python
################################################################################
# V1074
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
        return "CAT I"

    def get_rule_id(self):
        return ""

    def get_rule_version(self):
        return ""

    def get_group_id(self):
        return r"V-1074"

    def get_group_title(self):
        return ""

    def get_rule_title(self):
        return r"An approved virus scan program is not used and/or updated."

    def get_vulnerability_discussion(self):
        return r"Virus scan programs are a primary line of defense against the introduction of viruses and malicious code that can destroy data and even render a computer inoperable.  Utilizing the most current virus scan program provides the ability to detect this malicious code before extensive damage occurs.  Updated virus scan data files can help protect a system, because new viruses are identified by the software vendors on a monthly basis. Install approved virus scanning software.  Ensure the signature file is current."

    def set_verbose(self, verbose):
        self.__verbose = bool(verbose)

    def get_posture(self):
        return "Vista"

    def get_hippa(self):
        return "164.308(a)(5)(ii)(B)"
    
    def get_pci(self):
        return "5.1, 5.2"
    
    def get_hbs_id(self):
        return "HBSPCATVISTA000004"
    
    def get_dod8500_2(self):
        return "ECVP-1"

    def get_800_53(self):
        return "SI-3"
    
    def get_iso_27001(self):
        return "A.10.4.1, A.10.9.3"