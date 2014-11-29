#!/usr/bin/python
################################################################################
# PRESENTATION
# 
# Justin Dierking
# justindierking@hardbitsolutions.com
# phnomcobra@gmail.com
#
# Presentation module containing functions for generating HTML reports and 
# printing verbose finding information.
#
# 07/19/2014 Original construction
# 09/23/2014 Added industry standard IDs and implemented attribute based error
#            control
################################################################################

def print_verbose(finding):
    print ""
    print ""
    print ""
    print "#############################################"
    
    if hasattr(finding, "get_posture"):
        if not finding.get_posture() == "":
            print "# POSTURE:      " + finding.get_posture() 
    
    if hasattr(finding, "get_group_id"):
        if not finding.get_group_id() == "":
            print "# GROUP ID:     " + finding.get_group_id() 
    
    if hasattr(finding, "get_group_title"):
        if not finding.get_group_title() == "":
            print "# GROUP TITLE:  " + finding.get_group_title() 
    
    if hasattr(finding, "get_rule_id"):
        if not finding.get_rule_id() == "":
            print "# RULE ID:      " + finding.get_rule_id() 
    
    if hasattr(finding, "get_rule_version"):
        if not finding.get_rule_version() == "":
            print "# RULE VERSION: " + finding.get_rule_version() 
    
    if hasattr(finding, "get_severity"):
        if not finding.get_severity() == "":
            print "# SEVERITY:     " + finding.get_severity()
    
    if hasattr(finding, "get_hippa"):
        if not finding.get_hippa() == "":
            print "# HIPPA:        " + finding.get_hippa()
    
    if hasattr(finding, "get_pci"):
        if not finding.get_pci() == "":
            print "# PCI:          " + finding.get_pci()
    
    if hasattr(finding, "get_hbs_id"):
        if not finding.get_hbs_id() == "":
            print "# HBS:          " + finding.get_hbs_id()
    
    if hasattr(finding, "get_dod8500_2"):
        if not finding.get_dod8500_2() == "":
            print "# DoD 8500.2:   " + finding.get_dod8500_2()
    
    if hasattr(finding, "get_800_53"):
        if not finding.get_800_53() == "":
            print "# 800 53:       " + finding.get_800_53()
    
    if hasattr(finding, "get_iso_27001"):
        if not finding.get_iso_27001() == "":
            print "# ISO 27001:    " + finding.get_iso_27001()

    print "#############################################"
    
    if hasattr(finding, "get_rule_title"):
        if not finding.get_rule_title() == "":
            print ""
            print "TITLE:"
            print finding.get_rule_title()
    
    if hasattr(finding, "get_vulnerability_discussion"):
        if not finding.get_vulnerability_discussion() == "":
            print ""
            print "DISCUSSION:"
            print finding.get_vulnerability_discussion()
            
    print ""

def create_html_report(session_object, html_filename):
    html_file = open(html_filename, 'w')

    # HTML Header
    html_file.write('<!DOCTYPE html><html><head><style>\
                    .findings{border:1px solid black;border-collapse:collapse;}\
                    th,td{padding:5px;}\
                    </style></head><body>')

    # Title and uname table
    html_file.write('<table><tr><th><h1>PCAT2PY</h1></th><th>' + \
                    session_object.cli.system("uname -a") + \
                    '</th></tr></table>')

    # Start of findings table. Define the headings for compliance, id, h/f
    # and details.
    html_file.write('<table class="findings"><tr>\
                    <th class="findings">COMPLIANCE</th>\
                    <th class="findings" style="width:250px">ID</th>\
                    <th class="findings">H/F</th>\
                    <th class="findings">DETAILS</th></tr>')

    # Loop through the findings and query the compliance status, h/f,
    # severity, title, discussion, and output.
    for finding in session_object.findings:
        status = 'MANUAL'
        if hasattr(finding, 'get_compliance'):
            if finding.get_compliance():
                status = 'COMPLIANT'
            else: 
                status = 'NON-COMPLIANT'



        # Compliance        
        if status == 'COMPLIANT':
            html_file.write('<tr><td class="findings" style="background-color:rgb(0,255,0)">Closed</td>')
        elif status == 'NON-COMPLIANT' and finding.get_severity() == 'CAT I':
            html_file.write('<tr><td class="findings" style="background-color:rgb(255,0,0)">Open</td>')
        elif status == 'NON-COMPLIANT' and finding.get_severity() == 'CAT II': 
            html_file.write('<tr><td class="findings" style="background-color:rgb(255,127,0)">Open</td>')
        elif status == 'NON-COMPLIANT' and finding.get_severity() == 'CAT III': 
            html_file.write('<tr><td class="findings" style="background-color:rgb(255,255,0)">Open</td>')
        else: 
            html_file.write('<tr><td class="findings">Manual</td>')



        # Id
        html_file.write('<td class="findings">')
        
        if hasattr(finding, "get_posture"):
            if not finding.get_posture() == "":
                html_file.write("<b>POSTURE:</b> " + finding.get_posture() + "<br>")
        
        if hasattr(finding, "get_group_id"):
            if not finding.get_group_id() == "":
                html_file.write("<b>GROUP ID:</b> " + finding.get_group_id() + "<br>")
    
        if hasattr(finding, "get_group_title"):
            if not finding.get_group_title() == "":
                html_file.write("<b>GROUP TITLE:</b> " + finding.get_group_title() + "<br>") 

        if hasattr(finding, "get_rule_id"):
            if not finding.get_rule_id() == "":
                html_file.write("<b>RULE ID:</b> " + finding.get_rule_id() + "<br>") 

        if hasattr(finding, "get_rule_version"):
            if not finding.get_rule_version() == "":
                html_file.write("<b>RULE VERSION:</b> " + finding.get_rule_version() + "<br>") 

        if hasattr(finding, "get_hippa"):
            if not finding.get_hippa() == "":
                html_file.write("<b>HIPPA:</b> " + finding.get_hippa() + "<br>")

        if hasattr(finding, "get_pci"):
            if not finding.get_pci() == "":
                html_file.write("<b>PCI:</b> " + finding.get_pci() + "<br>")

        if hasattr(finding, "get_hbs_id"):
            if not finding.get_hbs_id() == "":
                html_file.write("<b>HBS:</b> " + finding.get_hbs_id() + "<br>")

        if hasattr(finding, "get_dod8500_2"):
            if not finding.get_dod8500_2() == "":
                html_file.write("<b>DoD 8500.2:</b> " + finding.get_dod8500_2() + "<br>")

        if hasattr(finding, "get_800_53"):
            if not finding.get_800_53() == "":
                html_file.write("<b>800 53:</b> " + finding.get_800_53() + "<br>")

        if hasattr(finding, "get_iso_27001"):
            if not finding.get_iso_27001() == "":
                html_file.write("<b>ISO 27001:</b> " + finding.get_iso_27001() + "<br>")

        html_file.write('</td>')



        # Does finding have a fix method
        if hasattr(finding, "fix"): 
            html_file.write('<td class="findings">Yes</td>')
        else: 
            html_file.write('<td class="findings">No</td>')



        # Title and discussion
        html_file.write('<td class="findings"><b>' + \
                        finding.get_rule_title() + '</b><br>' + \
                        finding.get_vulnerability_discussion() + '<i>')



        # Verbose output
        if hasattr(finding, "get_output"): 
            for line in finding.get_output(): 
                html_file.write('<br>' + line)



        # Conclude row
        html_file.write('</i></td></tr>')

    # Close remaining html tags
    html_file.write('</table></body></html>')

    html_file.close()