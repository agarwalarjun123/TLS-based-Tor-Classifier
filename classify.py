
from io import StringIO
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression




def process():
    df = pd.read_csv('csv/finaldata.csv')
    X = preprocess(df)
    
    Y = np.array(df['TOR'])
    X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size = 0.2)
    models = load_models()

    accuracy, precision, recall = {}, {}, {}
    for model_name in models.keys():
        models[model_name].fit(X_train,y_train)
        predictions = models[model_name].predict(X_test)
        accuracy[model_name] = accuracy_score(predictions, y_test)
        precision[model_name] = precision_score(predictions, y_test)
        recall[model_name] = recall_score(predictions, y_test)
    df_model = pd.DataFrame(index=models.keys(),columns=['Accuracy','Precision','Recall'])  
    df_model['Accuracy'] = accuracy.values()
    df_model['Precision'] = precision.values()
    df_model['Recall'] = recall.values()
    print(df_model)


def load_models():
    models = {}
    models['Logistic Regression'] = LogisticRegression()
    models['Support Vector Machines'] = LinearSVC()
    models['Decision Trees'] = DecisionTreeClassifier()
    models['Random Forest'] = RandomForestClassifier()
    models['Naive Bayes'] = GaussianNB()
    models['K-Nearest Neighbor'] = KNeighborsClassifier()
    return models
def preprocess(df):
    data = df[['tls_version','tls_max_client_tls_version','tls_cipher_suites_length','tls_supported_group_length','tls_key_share_length','tls_selected_group','tls_handshake_ciphersuite','tls_key_share_group','tls_ec_points_format_length','tls_sig_hash_alg_length','tls_cert_length','tls_cert_size','tls_handshake_extensions_length']].dropna(subset=['tls_version'])
    tls_version_dict = {'tls_version':{'0x304': 1.3,'0x303': 1.2,'0x0304': 1.3,'0x0303': 1.2},'tls_max_client_tls_version':{'0x304': 1.3,'0x303': 1.2,'0x0304': 1.3,'0x0303': 1.2},'tls_handshake_ciphersuite': {'0x1301': 1,'0xc030': 2,'0x1302': 3,'0xc02f': 4,'0xc02b': 5,'0xc02c': 6, '0x009d': 7,'0x0035': 8 }}
    data = data.replace(tls_version_dict)
    data = data.replace(np.nan,-1, regex=True)
    X = np.array(data)    
    return X

def test(data, reg_log_model):
    X = preprocess(data)
    y = reg_log_model.predict(X)
    print(y)
    
process()