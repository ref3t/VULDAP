from numpy.ma import count
import pandas as pd

import warnings, random
warnings.filterwarnings("ignore")

# implements TF-IDF

def main():
    
    dfCAPECAttack= pd.read_excel('./CAPECWithCwesDataandAttack.xlsx')
    dfCVECWE = pd.read_excel('./CVECWEWithDescriptionFinal.xlsx')
    
    dfCAPECAttack = dfCAPECAttack.loc[:, ["CAPECID", "Name", "Description",
    "Related Weaknesses"
]]  	

    dfCVECWE = dfCVECWE.loc[:,  ["CVEID", "CVEDescription", "CWE-ID", "CWE-Name"
                                , "CWE-Status", "CWE-Description",
    "CWE-Extended Description", "CWE-Related Weaknesses"
]]
    dfCVECWEMerged = pd.merge(dfCAPECAttack, dfCVECWE, left_on='Related Weaknesses', right_on='CWE-ID')
    
    dfCVECWEMerged.to_excel('./DataSetFinalCapecCve.xlsx', index=False)
    

if __name__ == "__main__":
    main()