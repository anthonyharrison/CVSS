#!/usr/bin/env python3

# Author: Anthony Harrison <anthony.p.harrison@gmail.com>
# License: MIT <https://opensource.org/licenses/MIT>
#
# Some simple utilities for manipulating CVSS (v3.1) base vectors
#

from cvsslib import cvss31, calculate_vector

# Global parameters
VERSION = "3.1"
BASE = "CVSS:"
SEPARATOR = "/"

PREAMBLE = BASE+VERSION+SEPARATOR

def parameter (name, value, end):
    # Utility function for generating parameter string
    global SEPARATOR
    # Separator added unless last parameter
    if end:
        return name + ":" + value
    else:
        return name + ":" + value + SEPARATOR

def CVSS_string (av,ac,pr,ui,s,c,i,a):
    # Generate CVSS vector string based on values for 8 mandatory parameters
    global PREAMBLE
    return PREAMBLE + \
        parameter("AV", av, False) + \
        parameter("AC", ac, False) + \
        parameter("PR", pr, False) + \
        parameter("UI", ui, False) + \
        parameter("S", s, False) + \
        parameter("C", c, False) + \
        parameter("I", i, False) + \
        parameter("A", a, True)

def CVSS_list (params):
    # Generate CVSS vector string based on Python list containing 8 mandatory parameters.
    # List order of parameters is AV, AC, PR, UI, S, C, I, A
    global PREAMBLE
    return PREAMBLE + \
        parameter("AV", params[0], False) + \
        parameter("AC", params[1], False) + \
        parameter("PR", params[2], False) + \
        parameter("UI", params[3], False) + \
        parameter("S", params[4], False) + \
        parameter("C", params[5], False) + \
        parameter("I", params[6], False) + \
        parameter("A", params[7], True)

def CVSS_score (vector):
    # Return base score for given CVSS vector string
    score = calculate_vector(vector, cvss31)
    # Returned list order is base score, temporal score, environmental score
    return score[0]

def CVSS_values (vector):
    # Split CVSS vector string into component parts and return list
    # Returned order of parameters is AV, AC, PR, UI, S, C, I, A
    global SEPARATOR
    param_str = []
    params = vector.split(SEPARATOR)
    for p in params:
        s = p.split(":")
        param_str.append (s[1])
    # Ignore first parameter which is CVSS version
    return param_str[1:]

def CVSS_modify_vector (original, modify):
    # Take CVSS vector (as a list) and update based on modify parameters
    # X in the modify list indicates no change to parameter value
    vector = []
    index = 0
    for m in modify:
        # Is parameter changing?
        if m != "X":
            # Updated parameter
            vector.append(m)
        else:
            # Parameter unchanged
            vector.append(original[index])
        index = index + 1
	# Return updated list of parameter values
    return vector

def CVSS_modify (vector, modify):
    # Take CVSS vector string and modify parameters according to modify list
    return CVSS_list(CVSS_modify_vector (CVSS_values(vector), modify))

def CVSS_modify_base_metrics(mod_string):
    mod_default = ["X", "X", "X", "X","X", "X", "X", "X"]
    parameters = {"MAV":0,"MAC":1,"MPR":2, "MUI":3, "MS":4, "MC":5, "MI":6, "MA":7}
    params = mod_string.split(SEPARATOR)
    for p in params:
        s = p.split(":")
        # s[0] is paramerter name, s[1] is parameter values
        if s[0] in parameters:
            # Index = parameters[s[0]]
            # Update with values
            mod_default[parameters[s[0]]] = s[1]
    return mod_default

# Main
if __name__ == "__main__":
    print ("CVSS Utilities")
    print (CVSS_modify_base_metrics("MAV:H/MC:N"))

# END
