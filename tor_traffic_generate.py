
import time
import subprocess
import traceback
import uuid

torBundlePath = "/home/arjun/Downloads/tor-browser_en-US/Browser/start-tor-browser"
def startSession():
    try:
        uid = uuid.uuid4()
        proc = subprocess.Popen(['tcpdump','-i','enp0s9', '-w','dataset/'+str(uid)+'.pcap'])
        browserProcess = subprocess.Popen([torBundlePath,'--detach'])
        time.sleep(10)
        subprocess.Popen(['pkill','-15', 'firefox'])
        browserProcess.terminate()
        proc.terminate()
    except:
        traceback.print_exc()
        pass
for i in range(50):
    startSession()
    time.sleep(5)