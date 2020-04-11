#!/usr/bin/env python3

# Author: Anthony Harrison <anthony.p.harrison@gmail.com>
# License: MIT <https://opensource.org/licenses/MIT>
#
# A simple script that generates all of the CVSS (v3.1) base vectors and assoicated base score value
#

import cvssutils

# Base score parameters
# =====================

# Attack vector
AV = ["N", "A", "L", "P"]
# Attack Commplexity
AC = ["L", "H"]
# Priviledges Required
PR = ["N", "L", "H"]
# User Interaction
UI = ["N", "R"]
# Scope
S = ["U", "C"]
# Confidentiality
C = ["H", "L", "N"]
# Integrity
I = ["H", "L", "N"]
# Availability
A = ["H", "L", "N"]

CVSS_parameters = [AV, AC, PR, UI, S, C, I, A]

def generate_all_CVSSstrings(modify):
    # Generate all CVSS vector strings and base scores
    count=0
    for av in AV:
        for ac in AC:
            for pr in PR:
                for ui in UI:
                    for s in S:
                        for c in C:
                            for i in I:
                                for a in A:
                                    vector = cvssutils.CVSS_string(av,ac,pr,ui,s,c,i,a)
                                    if len(modify) > 0:
                                        mv = cvssutils.CVSS_modify(vector, modify)
                                        print (vector, cvssutils.CVSS_score(vector), cvssutils.CVSS_score(mv))
                                    else:
                                        print (vector, cvssutils.CVSS_score(vector))                                   
                                    count = count + 1
    print ("Total number of strings", count)

if __name__ == "__main__":
	generate_all_CVSSstrings([])
	# And see change if modified parameters
	generate_all_CVSSstrings(['L', 'X', 'X', 'X', 'X', 'H', 'H', 'H'])
	
# END