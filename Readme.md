<!-- @format -->

## TLS BASED TOR CLASSIFIER

Tor Classifier on TLS Features with 99% Overall Accuracy. Repository contains the dataset,scripts used to parse the raw dataset into CSV, and classifier CLI to train and test flows.

Download Dataset from https://gla-my.sharepoint.com/:u:/g/personal/2654219a_student_gla_ac_uk/EWbY_iXWpJFGtqvclfAhrOIBsmNe325q9lBVRbGr1MlFAA?e=7g03DM

### PREREQUISITE

1. python 3.7
2. wireshark

### STEPS TO TRAIN THE DATASET

1. Setup VirtualEnv and install python packages.

```sh
python3 -m virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Parse Flows from Captured Dataset.

```sh
python3 parse.py pcaps/<fileName>.pcap
```

3. Create training.csv by combining tor and non-tor generated csv files and add Tor Label as 1/0. (for simplicity sharing training.csv).

4. Train dataset

```sh
python3 classify.py -m train -i csv/training.csv
```

### STEPS TO TEST THE CLASSIFIER

1. Parse Flows from Captured testing pcap file.

```sh
python3 parse.py pcaps/<fileName>.pcap
```

2. Run the Classifier (Output will contain extra column with label - 1 (Tor) / 0 (Non-Tor))

```sh
python3 classify.py -m test -a MODEL_NAME -i csv/<fileName>.csv -o csv/result.csv
```

MODELS = Support_Vector_Machines,Decision_Trees,Random_Forest,Naive_Bayes,K_Nearest_Neighbor

### STEPS TO RUN INFERENCE LATENCY EXPERIMENT

1. Run time_experiment.py - Graph would be outputted.

```sh
python3 time_experiment.py
```

### STEPS TO RUN THE TOR TRAFFIC GENERATOR

Note: Will work only on MAC / Linux.

1. Update "torBundlePath" in tor_traffic_generate.py to the path of the bundle.
2. Run the tor_traffic_generate.py

```bash
python3 tor_traffic_generate.py
```
