# CVSS

A utility for reporting and manipulating CVSS v3 metrics

The motivation for this tool came from looking for a simple command line tool to report the CVSS base score metric for a given CVE and asking the question 'how does that score apply in my environment'. The CVSS V3 specification includes a modify base score string to address this question.

This utility extracts the CVE vector from NVD JSON record for the CVE.

This utility only works for CVSS V3. If the CVE record does not have CVSS V3 record and error is returned.

Documentation of the CVSS v3.1 [specification](https://www.first.org/cvss/v3.1/specification-document).

# Installation

Only Python 3 is supported.

pip -r requirements.txt

# Usage

 python CVSS.py [-h] [-C CVE] [-m MOD_VECTOR] [-b] [-e] [-i] [-s] [-V] [-v]

 optional arguments:
   -h, --help            show this help message and exit
   -C CVE, --CVE CVE     CVE Identity
   -m MOD_VECTOR, --modify MOD_VECTOR
                         Modified CVSS Base Metric string (e.g. MAV:L/MC:H)
   -b, --base            Report base score (default)
   -e, --exploit         Report exploit score
   -i, --impact          Report impact score
   -s, --string          Report CVSS Vector String
   -V, --verbose         Verbose reporting
   -v, --version         Show version information and exit

Apart from -C option all arguments are optional.

# Examples

python CVSS.py -C CVE-2020-0001

Returns the CVE base score

python CVSS.py -C CVE-2020-0001 -V

Verbose reporting of the CVE base score

python CVSS.py -C CVE-2020-0001 -i -e

Returns the CVE base, impact and exploitability scores

python CVSS.py -C CVE-2020-0001 -m "MAV:L/MC:H"

Report the modified CVE base score  

# Error Messages

[ERROR] CVE parameter not specified.

The -C parameter was not specified

[ERROR] No CVE record for <CVE> found

The specified CVE does not exist

[ERROR] No CVSSv3 data for <CVE>

A CVSSv3 record was not found for the specified CVE although there may be a CVSSv2 record.

ERROR] Invalid JSON received for CVE <CVE>

The NVD JSON record for CVE was not valid

[ERROR] Discrepancy between base score calculations for CVE <CVE>

Internal error

# Information Messages

Various information messages are produced when Verbose mode is selected

# Licence

 MIT Licence

 Referenced components may be released under different licences.

# Extra

The 'docs' directory contains the base score calculation for all of the CVSS V3 base score strings (all 2592 combinations).

# Postscript

 This was a simple exercise to get experience in publishing a utility on GitHub in the hope that it might be useful to someone. I know that there are much better ways of writing the code but hopefully the code is clear if anyone wants to take it to the next stage.
