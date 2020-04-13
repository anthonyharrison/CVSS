#!/usr/bin/env python3

# Author: Anthony Harrison <anthony.p.harrison@gmail.com>
# License: MIT <https://opensource.org/licenses/MIT>
#
# Some tests to check  utilities for manipulating CVSS (v3.1) base vectors
#

import cvssutils

def test1():
    # Create CVSS vector string and base score
    vector = cvssutils.CVSS_string("N", "L", "N", "N", "C", "L", "L", "L")
    print (vector, cvssutils.CVSS_score(vector))

def test2():
    # Prove string conversion to list results in same score
    vector = cvssutils.CVSS_string("N", "L", "N", "N", "C", "L", "L", "L")
    score = cvssutils.CVSS_score(vector)
    x = cvssutils.CVSS_values(vector)
    vector2 = cvssutils.CVSS_list(x)
    score2 = cvssutils.CVSS_score(vector2)
    print (vector, score)
    print (vector2, score2)

def test3():
    # Modify parameters within vector
    vector = cvssutils.CVSS_string("N", "L", "N", "N", "C", "L", "L", "L")
    x = cvssutils.CVSS_values(vector)
    # Modification string X indicates don't change
    m = ['X', 'X', 'X', 'X', 'X', 'H', 'H', 'H']
    mv = cvssutils.CVSS_modify_vector (x, m)
    print (x)
    print (mv)
    vector3 = cvssutils.CVSS_list(mv)
    score3 = cvssutils.CVSS_score(vector3)
    print (vector, cvssutils.CVSS_score(vector))
    print (vector3, score3)

def test4():
    vector = cvssutils.CVSS_string("N", "L", "N", "N", "C", "L", "L", "L")
    modify_params = ['L', 'X', 'X', 'X', 'X', 'H', 'H', 'H']
    print (vector)
    mv = cvssutils.CVSS_modify(vector, modify_params)
    print (mv)
    print (cvssutils.CVSS_score(vector), cvssutils.CVSS_score(mv))

def test5():
    # Two different ways of specifying modification to base metrics
    modify_params = ['L', 'X', 'X', 'X', 'X', 'H', 'H', 'H']
    modify = cvssutils.CVSS_modify_base_metrics("MAV:L/MC:H/MI:H/MA:H")
    print (modify_params)
    print (modify)

# Main
if __name__ == "__main__":
    print ("CVSS Utils Testing")
    test1()
    test2()
    test3()
    test4()
    test5()

# END
