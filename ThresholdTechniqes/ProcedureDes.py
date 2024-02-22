import pandas as pd
import re
from gensim.parsing.preprocessing import preprocess_documents
from sklearn.metrics.pairwise import cosine_similarity
from openpyxl import Workbook
import xlsxwriter
import numpy as np
import random
import itertools
from transformers import AutoTokenizer, AutoModel
from sklearn.metrics.pairwise import cosine_similarity
import torch
from sklearn.feature_extraction.text import TfidfVectorizer
# from app.core.vulDataClass  import VulData
from vulDataClass  import VulData
from sentence_transformers import SentenceTransformer, util
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import PorterStemmer, WordNetLemmatizer
nltk.download('stopwords')
nltk.download('punkt')
nltk.download('wordnet')

def readProcedures():

    file_pathPositive = 'NewMapping/FinalResultSeperate/Procedures/Procedures.xlsx'
    # Read the Excel file
    data = pd.read_excel(file_pathPositive, header=0, names=['ProceduresID', 'ProcedureDescription'])
    
    # Group by 'ID' and aggregate other columns into lists
    grouped_data = data.groupby('ProceduresID').agg(lambda x: x.tolist()).reset_index()

    # Create a dictionary from the grouped data
    data_dictP = grouped_data.set_index('ProceduresID').to_dict(orient='index')
    # Return the dictionary if needed
    return data_dictP

def readCAPEC():
    file_pathPositive = 'NewMapping/FinalResultSeperate/CAPEC/CAPEC.xlsx'
    # Read the Excel fileCAPECID	CAPECName	CAPECDescription

    data = pd.read_excel(file_pathPositive, header=0, names=['CAPECID', 'CAPECName', 'CAPECDescription'])
    
    # Group by 'ID' and aggregate other columns into lists
    grouped_data = data.groupby('CAPECID').agg(lambda x: x.tolist()).reset_index()

    # Create a dictionary from the grouped data
    data_dictP = grouped_data.set_index('CAPECID').to_dict(orient='index')
    # Return the dictionary if needed
    return data_dictP

import re

df = pd.DataFrame(columns=['ProceduresID','ProcedureDescription'])


def checkCVEUsingAllTech():
    global df
    tech_dict = readProcedures()
    
    proceduresId = []  
    for key, value in tech_dict.items():
        if key not in proceduresId:
            proceduresId.append(key)                    
            df = pd.concat([df, pd.DataFrame({'ProceduresID':[key],'ProcedureDescription':[value['ProcedureDescription'][0]]})], ignore_index=True)

    df.to_excel(f"NewMapping/FinalResultSeperate/Procedures/ProceduresWithoneDesPositives.xlsx", index=False)

checkCVEUsingAllTech()
