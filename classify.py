
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import OrdinalEncoder, LabelEncoder
import os
import pickle
import argparse

def train(FILE_NAME):
    df = pd.read_csv(FILE_NAME)
    X = preprocess(df)
    Y = np.array(df['TOR'])
    X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size = 0.33, random_state=100)
    models = load_models(True)
    accuracy, precision, recall = {}, {}, {}
    for model_name in models.keys():
        models[model_name].fit(X_train,y_train)
        predictions = models[model_name].predict(X_test)
        accuracy[model_name] = accuracy_score(predictions, y_test)
        precision[model_name] = precision_score(predictions, y_test)
        recall[model_name] = recall_score(predictions, y_test)
        print("confusion_matrix",confusion_matrix(y_test, predictions))
    df_model = pd.DataFrame(index=models.keys(),columns=['Accuracy','Precision','Recall'])  
    df_model['Accuracy'] = accuracy.values()
    df_model['Precision'] = precision.values()
    df_model['Recall'] = recall.values()
    print(df_model)
    for model in models:
        filename = 'models/{}.sav'.format(model)
        pickle.dump(models[model],open(filename,'wb'))
def load_models(train = False):
    models = {}
    models['Support_Vector_Machines'] =  pickle.load(open('models/Support_Vector_Machines.sav','rb')) if os.path.exists('models/Support_Vector_Machines.sav') and not train else LinearSVC()
    models['Logistic_Regression'] =  pickle.load(open('models/Logistic_Regression.sav','rb')) if os.path.exists('models/Logistic_Regression.sav') and not train else LogisticRegression(max_iter=1000)
    models['Decision_Trees'] = pickle.load(open('models/Decision_Trees.sav','rb')) if os.path.exists('models/Decision_Trees.sav') and not train else DecisionTreeClassifier()
    models['Random_Forest'] = pickle.load(open('models/Random_Forest.sav','rb')) if os.path.exists('models/Random_Forest.sav') and not train else RandomForestClassifier()
    models['Naive_Bayes'] = pickle.load(open('models/Naive_Bayes.sav','rb')) if os.path.exists('models/Naive_Bayes.sav') and not train else GaussianNB()
    models['K_Nearest_Neighbor'] = pickle.load(open('models/K_Nearest_Neighbor.sav','rb')) if os.path.exists('models/K_Nearest_Neighbor.sav') and not train else KNeighborsClassifier()
    return models
def preprocess(df):
    df = df[['tls_version','tls_max_client_tls_version','tls_cipher_suites_length','tls_supported_group_length','tls_key_share_length','tls_selected_group','tls_handshake_ciphersuite','tls_key_share_group','tls_ec_points_format_length','tls_sig_hash_alg_length','tls_cert_length','tls_cert_size','tls_handshake_extensions_length']].dropna(subset=['tls_version'])
    ohe = LabelEncoder()
    df['tls_version'] = ohe.fit_transform(df['tls_version'])
    ohe = LabelEncoder()
    df['tls_max_client_tls_version'] = ohe.fit_transform(df[['tls_max_client_tls_version']])
    ohe = LabelEncoder()
    df['tls_handshake_ciphersuite'] = ohe.fit_transform(df[['tls_handshake_ciphersuite']])
    # tls_version_dict = {'tls_version':{'0x304': 1.3,'0x303': 1.2,'0x0304': 1.3,'0x0303': 1.2},'tls_max_client_tls_version':{'0x304': 1.3,'0x303': 1.2,'0x0304': 1.3,'0x0303': 1.2},'tls_handshake_ciphersuite': {'0x1301': 1,'0xc030': 2,'0x1302': 3,'0xc02f': 4,'0xc02b': 5,'0xc02c': 6, '0x009d': 7,'0x0035': 8 }}
    # data = data.replace(tls_version_dict)
    data = df.replace(np.nan,-1, regex=True)
    X = np.array(data)
    return X
def test(modelName, TEST_FILE_PATH, RESULT_FILE_PATH):
    df = pd.read_csv(TEST_FILE_PATH).dropna(subset=['tls_version'])
    X = preprocess(df)
    models = load_models()
    if modelName not in models:
        raise Exception('modelName does not exist.')
    df['TOR'] = models[modelName].predict(X)
    df.to_csv(RESULT_FILE_PATH)

if __name__ == '__main__':
    pcapparser = argparse.ArgumentParser(description='classifies a flow as TOR/non-TOR')
    pcapparser.add_argument('-m',
                       action='store',
                       choices=['train', 'test'],
                       help='set the mode of the classifier', required=True)
    pcapparser.add_argument("-i", "--input", required=True,
        help="input csv file", metavar="FILE")
    args,_=pcapparser.parse_known_args()
    pcapparser.add_argument("-o", "--output", required=args.m == 'test',
        help="output csv file path", metavar="FILE")
    pcapparser.add_argument("-a", required=args.m == 'test', choices=("Support_Vector_Machines","Decision_Trees",'Random_Forest','Naive_Bayes','K_Nearest_Neighbor'))
    args,_ = pcapparser.parse_known_args()
    if args.m == 'train':
        train(args.input)
    elif args.m == 'test':
        test(args.a,args.input,args.output)

    
