# VULDAP
VULDAP is a novel approach proposed in the current repository. VULDAP stands for Automated Vulnerability Detection From Cyberattack Patterns. It is a method that uses natural language processing and machine learning techniques to recommend software vulnerabilities from textual descriptions of cyberattacks patterns. VULDAP can help cybersecurity experts to identify and prioritize vulnerabilities based on real threats and to develop more effective mitigation strategies. VULDAP uses information from the MITRE repositories, such as CAPEC, CWE, and CVE, to create a dataset of attacks and vulnerabilities. VULDAP also uses a sentence transformer model to compute semantic similarity between attack pattern  and vulnerability descriptions and to produce a ranked list of relevant CVEs.

# Data Description
The VULDAP approach uses three datasets from the MITRE repositories, which are:

- CAPEC: A catalogue of common attack patterns, tactics, and techniques adversaries use to exploit vulnerabilities. It provides a common language for describing and analyzing cyberattacks.
- CWE: A community-developed collection of common software weaknesses, coding errors, and security flaws. It provides a standard framework for identifying and classifying software vulnerabilities and their root causes.
- CVE: A list of publicly known cybersecurity vulnerabilities and exposures, each with a unique identification number and a brief description. It provides a reference point for vulnerability information and facilitates information sharing among security communities.



# HOW To Use The Scripts
Pre-Requirements
  - Python3
  - sklearn
  - gensim
  - numpy
  - nltk
    


