import pandas as pd
from classify import load_models, preprocess
import time
import numpy as np
import matplotlib.pyplot as plt

def run_experiment():
    df = pd.read_csv('csv/training.csv')
    df_sample = df.sample(n = 300, random_state= 100)
    models = load_models()
    score_time_dict = {}
    for model_name in models:
        time_array = []
        for i in range(0,100):
            start_time = time.time()
            X = preprocess(df.iloc[[i]])
            models[model_name].predict(X)
            time_array.append((time.time() - start_time) * 1000)
        score_time_dict[model_name] = np.mean(time_array)
    show_charts(score_time_dict)

def show_charts(score_dict):
    y = score_dict.values()
    x = score_dict.keys()
    plt.bar(x, y)
    plt.show()

if __name__ == '__main__':
    run_experiment()