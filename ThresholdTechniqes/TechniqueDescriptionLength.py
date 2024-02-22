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

def readTactics():
    file_pathPositive = 'NewMapping/FinalResultSeperate/Tactic/FinalTacticPositive.xlsx'
    # Read the Excel file
    data = pd.read_excel(file_pathPositive, header=0, names=['TacticId', 'TacticName', 'TacticDescription'])
    
    # Group by 'ID' and aggregate other columns into lists
    grouped_data = data.groupby('TacticId').agg(lambda x: x.tolist()).reset_index()

    # Create a dictionary from the grouped data
    data_dictP = grouped_data.set_index('TacticId').to_dict(orient='index')
    # Return the dictionary if needed
    return data_dictP

def readsubTechniques():
    file_pathPositive = 'NewMapping/FinalResultSeperate/SubTechniques/FinalSubTechniquesPositive.xlsx'
    # Read the Excel file
    data = pd.read_excel(file_pathPositive, header=0, names=['TechnqiueID', 'TechnqiueName', 'TechnqiueDescription'])
    
    # Group by 'ID' and aggregate other columns into lists
    grouped_data = data.groupby('TechnqiueID').agg(lambda x: x.tolist()).reset_index()

    # Create a dictionary from the grouped data
    data_dictP = grouped_data.set_index('TechnqiueID').to_dict(orient='index')
    count = 0
    for key, value in data_dictP.items():
        print(f"{count}ID: {key}\tTechnique: {value['TechnqiueName']}\tDescription: {value['TechnqiueDescription']}")
        count = count +1
    return data_dictP

def readTechWithNegative():
    file_pathPositive = 'NewMapping/FinalResultSeperate/Techniqes/FinalTechniquesPositive.xlsx'
    # Read the Excel file
    data = pd.read_excel(file_pathPositive, header=0, names=['TechnqiueID', 'TechnqiueName', 'TechnqiueDescription'])
    
    # Group by 'ID' and aggregate other columns into lists
    grouped_data = data.groupby('TechnqiueID').agg(lambda x: x.tolist()).reset_index()

    # Create a dictionary from the grouped data
    data_dictP = grouped_data.set_index('TechnqiueID').to_dict(orient='index')

    file_pathNegative = 'NewMapping/FinalResultSeperate/Techniqes/FinalTechniquesNegative.xlsx'
    data = pd.read_excel(file_pathNegative, header=0, names=['TechnqiueID', 'TechnqiueName', 'TechnqiueDescription'])
    grouped_data = data.groupby('TechnqiueID').agg(lambda x: x.tolist()).reset_index()
    data_dictNegative = grouped_data.set_index('TechnqiueID').to_dict(orient='index')

    # Convert dictionary items to a list
    dict_items = list(data_dictNegative.items())

    # Randomly select 59 items
    random_items = random.sample(dict_items, 59)

    # Convert the selected items back to a dictionary
    data_dictNegative = dict(random_items)
    count = 0
    # data_dictP.update(data_dictNegative)
     # Print the resulting dictionary using a for loop
    for key, value in data_dictP.items():
        print(f"{count}ID: {key}\tTechnique: {value['TechnqiueName']}\tDescription: {value['TechnqiueDescription']}")
        count = count +1

    # Return the dictionary if needed
    return data_dictP

import re


def remove_citations_and_urls(text):
    
    citation_pattern = r'\(Citation:.*?\)'

    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'

    citations = re.findall(citation_pattern, text)

    for citation in citations:
        text = text.replace(citation, '')

    urls = re.findall(url_pattern, text)

    for url in urls:
        text = text.replace(url, '')
    regex = "^<code>.*</code>$"
    text = re.sub(regex, "",text, flags=re.MULTILINE) 
    text = " ".join(text.split()) 
    text = re.sub("[^A-Za-z0-9]", " ", text) 
    return text

def removeUrls (text):
    text = re.sub(r'(https|http)?:\/\/(\w|\.|\/|\?|\=|\&|\%)*\b', '', text, flags=re.MULTILINE)
    text = re.sub(r'(?i)NOTE:.*', '', text)
    text = re.sub(r'\b\d+(\.\d+)*\b', '', text) 
    return(text)


def removeCitation(text):
    position = text.find('(Citation:')
    if position > 0:
        return text[:position]
    else:
        return text

def removeURLandCitationBulk(texts):
    return [remove_citations_and_urls(text) for text in texts]
# red = removeURLandCitationBulk(['Untrusted search path vulnerability in  PGP Desktop 9.9.0 Build 397, 9.10.x, 10.0.0 Build 2732,and probably other versions allows local users,and possibly remote attackers,to execute arbitrary code and conduct DLL hijacking attacks via a Trojan horse tsp.dll or tvttsp.dll that is located in the same folder as a .p12,.pem,.pgp,.prk,.prvkr,.pubkr,.rnd or .skr file.'])

def dataPreprocessingStopWords(texts):
    return [preprocess_text_stop_words(text) for text in texts]

def dataPreprocessingStemming(texts):
    return [preprocess_text_stemming(text) for text in texts]

def dataPreprocessingLemmatization(texts):
    return [preprocess_text_lemmatization(text) for text in texts]

def preprocess_text_stop_words(text):
    # Tokenization
    tokens = word_tokenize(text)
    stop_words = set(stopwords.words('english'))

    # Stop words removal
    tokens = [token for token in tokens if token not in stop_words]
        
    return tokens
#Stemming is the process of finding the root of words
def preprocess_text_stemming(text):
    # Tokenization
    tokens = word_tokenize(text)
    stemmer = PorterStemmer()
    # Stemming
    stemmed_tokens = [stemmer.stem(token) for token in tokens]
    
    return stemmed_tokens
#Lemmatization is the process of finding the form of the related word in the dictionary.
def preprocess_text_lemmatization(text):
    # Tokenization
    tokens = word_tokenize(text)
    
    lemmatizer = WordNetLemmatizer()
    # Lemmatization
    lemmatized_tokens = [lemmatizer.lemmatize(token) for token in tokens]
    
    return lemmatized_tokens
df = pd.DataFrame(columns=['ThechID','TechDescriptionBefore','countBefore','TechDescriptionAfter','countAfter'])


def checkCVEUsingAllTech():
    global df
    # informationData = ["Tactic", "Technique","subTechniques","Procedures","CAPEC"]
    informationData = ["Technique"]
    for infoData in informationData:
        if infoData == "Tactic":
            tech_dict = readTactics()
        elif infoData == "Technique":
            tech_dict = readTechWithNegative()
        elif infoData == "subTechniques":
            tech_dict = readsubTechniques()
        elif infoData == "Procedures":
            tech_dict = readProcedures()
        elif infoData == "CAPEC":
            tech_dict = readCAPEC()
    
        
        for key, value in tech_dict.items():
        #     for key, value in attach_dict.items():
        # print(f"{count}TechnqiueID: {key}\tTechnique: {value['TechnqiueName']}\tDescription: {value['TechnqiueDescription']}")
            print(f"ID: {key} ttttt ")
            # if countT >4:
            #     break
            attack_texts = []
            if infoData == "Tactic":
                # attack_texts = removeURLandCitationBulk([f"{value['TacticName']} {value['TacticDescription']}"])
                attack_texts = removeURLandCitationBulk([f"{value['TacticDescription']}"])
            elif infoData == "Procedures":
                attack_texts = removeURLandCitationBulk([f"{value['ProcedureDescription']}"])
            elif infoData == "CAPEC":
                # attack_texts = removeURLandCitationBulk([f"{value['CAPECName']} {value['CAPECDescription']}"])
                attack_texts = removeURLandCitationBulk([f"{value['CAPECDescription']}"])
            else:
                attack_texts = removeURLandCitationBulk([f"{value['TechnqiueName']} {value['TechnqiueDescription']}"])
            attack_texts = dataPreprocessingStemming(attack_texts)
            attack_texts = [' '.join(item) for item in attack_texts]        
            df = pd.concat([df, pd.DataFrame({'ThechID':[key],'TechDescriptionBefore':[value['TechnqiueDescription'][0]],'countBefore':[len(value['TechnqiueDescription'][0])],'TechDescriptionAfter':[attack_texts[0]],'countAfter': [len(attack_texts[0])]})], ignore_index=True)

        df.to_excel(f"NewMapping/OutResults/CountTechDescription{infoData}.xlsx", index=False)

checkCVEUsingAllTech()
