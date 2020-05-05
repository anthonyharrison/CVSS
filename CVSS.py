#!/usr/bin/env python3

# Author: Anthony Harrison <anthony.p.harrison@gmail.com>
# License: MIT <https://opensource.org/licenses/MIT>
#
# A simple, quick script that extracts the CVSS metrics data for a specified CVE
# and provides an optional updated base score based on a modified CVSS base metric vector
#
# Uses CVE JSON files found at: https://github.com/olbat/nvdcve/tree/master/nvdcve
#
# Usage: python cvss.py -C <CVE-ID> -m <Modified vector> -V
#
# where CVE_ID is in form CVE-YYYY-NNNN
#       Example Modified Vector is "MAC:N/MC:H"
#
#       -b Report base score (Default)
#       -e Report exploit score
#       -i Report impact score
#       -s Report CVSS Vector String
#       -V Verbose reporting
#       -v Show version information
#       -h Help information
#

import argparse
import json
import logging
import sys
import urllib.request
from json.decoder import JSONDecodeError
from socket import gaierror
from urllib.error import HTTPError, URLError

import cvssutils

VERSION = "0.1"

def get_CVE_record(CVE):
    # Get CVSS scores for specified CVE format is CVE-YYYY-NNNN
    # Base URL for where the JSON file for each CVE is stored
    BASE_URL = "https://olbat.github.io/nvdcve/"
    scores = {}
    url = BASE_URL + CVE + ".json"
    try:
        with urllib.request.urlopen(url) as response:
            if response.status == 200:
                # Try to parse the response for the CVE
                try:
                    cve_data = json.loads(response.read())
                except JSONDecodeError as e:
                    print("[INFO] Invalid JSON Received for", CVE)
                    # Fetch the CVSS v3 info where possible
                try:
                    if cve_data["impact"]["baseMetricV3"]:
                        scores = {
                        "base_score": cve_data["impact"]["baseMetricV3"]["cvssV3"]["baseScore"],
                        "vector_string": cve_data["impact"]["baseMetricV3"]["cvssV3"]["vectorString"],
                        "impact_score": cve_data["impact"]["baseMetricV3"]["impactScore"],
                        "exploitability_score": cve_data["impact"]["baseMetricV3"]["exploitabilityScore"],
                        }
                except KeyError as e:
                    print("[INFO] Couldn't find CVSSv3 data for", CVE)
                    # Fetch the CVSS v2 info where possible
                    try:
                        if cve_data["impact"]["baseMetricV2"]:
                            # Collate the scores into a dict
                            scores = {
                            "base_score": cve_data["impact"]["baseMetricV2"]["cvssV2"]["baseScore"],
                            "vector_string": cve_data["impact"]["baseMetricV2"]["cvssV2"]["vectorString"],
                            "impact_score": cve_data["impact"]["baseMetricV2"]["impactScore"],
                            "exploitability_score": cve_data["impact"]["baseMetricV2"]["exploitabilityScore"],
                            }
                    except KeyError as e:
                        print("[INFO] Couldn't find CVSSv2 data for", CVE)

    except (HTTPError, URLError, gaierror) as e:
        # If there is an error making the web request, just move on
        print("[INFO] CVSS info not found for", CVE)
    return scores

def info_report(text,value,verbose):
    if verbose:
        print ("[INFO]" + text,value)
    else:
        print (value)

# Main
if __name__ == "__main__":

    verbose = False
    modify = False
    base = True
    exploit = False
    impact = False
    vector_string = False
    mod_vector = None
    cve = None
    desc = "CVSS Score"

    # Set all parser arguments here.
    parser  =  argparse.ArgumentParser(formatter_class = argparse.RawDescriptionHelpFormatter, description = desc)

    parser.add_argument("-C","--CVE", help = "CVE Identity", dest = 'cve')
    parser.add_argument("-m","--modify", help = "Modified CVSS Base Metric string (e.g. MAV:H/MC:H)", dest = 'mod_vector')
    parser.add_argument("-b","--base", help = "Report base score (default)", dest = 'base', action = "store_true")
    parser.add_argument("-e","--exploit", help = "Report exploit score", dest = 'exploit', action = "store_true")
    parser.add_argument("-i","--impact", help = "Report impact score", dest = 'impact', action = "store_true")
    parser.add_argument("-s","--string", help = "Report CVSS Vector String", dest = 'vector_string', action = "store_true")
    parser.add_argument("-V","--verbose", help = "Verbose reporting", dest = 'verbose', action = "store_true")
    parser.add_argument("-v","--version", help = "Show version information and exit", dest = 'version', action = "store_true")

    # Parse arguments in case they are provided.
    params = parser.parse_args()
    cve = params.cve
    verbose = params.verbose
    version = params.version
    #base = params.base
    exploit = params.exploit
    impact = params.impact
    vector_string = params.vector_string
    cve = params.cve
    mod_vector = params.mod_vector

    # Validate parameters
    if cve == None:
        # No CVE specified
        print ("[ERROR] CVE parameter not specified")
        sys.exit(-1)

    if mod_vector != None:
        modify = True

    if version:
        print (desc,": version",VERSION)
        sys.exit()

    scores = get_CVE_record(cve)
    # Check that we have some data
    if len(scores) == 0:
        # No record found
        print ("[ERROR] No record for",cve,"found")
        sys.exit(-1)

    # Validate the calculated base score matches the value stored with the CVE record
    base_score = cvssutils.CVSS_score(scores["vector_string"])
    if  base_score != scores["base_score"]:
        # Interesting....probably because CVE reported using V2 metrics
        print ("[ERROR] Discrepancy between base score calculations for CVE",cve,". CVE Record is",scores["base_score"]," Calculated is",base_score)
        sys.exit(1)

    if modify:
        # Now modify the CVSS vestor and calculate the updated score
        modified_base_score = cvssutils.CVSS_score(cvssutils.CVSS_modify(scores["vector_string"], cvssutils.CVSS_modify_base_metrics(mod_vector)))
        if verbose:
            print ("[INFO] Original Base Score",scores["base_score"])
        info_report("Modified Base Score",modified_base_score,verbose)
    if base:
        info_report("Base Score",base_score,verbose)
    if exploit:
        info_report("Exploit Score",scores["exploitability_score"],verbose)
    if impact:
        info_report("Impact Score",scores["impact_score"],verbose)
    if vector_string:
        info_report("CVSS vector",scores["vector_string"],verbose)
# end
