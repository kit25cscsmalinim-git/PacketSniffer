from flask import Flask, render_template, jsonify
from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from datetime import datetime
import threading

app = Flask(__name__)

packets = []

def process_packet(packet):
    try:
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst

        elif packet.haslayer(IPv6):
            src = packet[IPv6].src
            dst = packet[IPv6].dst

        else:
            return

        data = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "src": src,
            "dst": dst,
            "protocol": packet.summary()
        }

        packets.append(data)

    except:
        pass

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/packets")
def get_packets():
    return jsonify(packets[-20:])

def start_sniffing():
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    t = threading.Thread(target=start_sniffing)
    t.daemon = True
    t.start()

    app.run(debug=True)
