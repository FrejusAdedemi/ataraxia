from flask import Flask, jsonify, render_template
from flask_cors import CORS
import os
import json
import traceback
import requests
# Modules perso
from modules.return_file import download_file
from modules.initial_acces_service import extract_pcap_info, envoyer_donnees_pcap
from modules.ip_private_connections import analyze_pcap_and_ip
from modules.ip_connections import public_access
from modules.appli_request import analyze_malware, parse_tshark_output
from modules.countryCode import get_country_info, format_json
from modules.map_api import map_generator
from modules.certificate_detection import pcap_to_json
from modules.check_ip import threat_score
from modules.ip_public_analyze import get_ip_analysis
from modules.map_generator import extract_ip_info

app = Flask(__name__)
CORS(app)  # Pour permettre les requêtes cross-origin

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/init_access")
def initial_access():
    try:
        file_path = download_file()
        data = extract_pcap_info(file_path)

        # Si extract_pcap_info() retourne une string JSON :
        if isinstance(data, str):
            data = json.loads(data)

        return jsonify({
            "initial_access": data,
            "message": "🎯 Analyse terminée"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/private_access/<ip_address>")
def private_access(ip_address):
    try:
        print(f"📥 Analyse des connexions privées pour IP: {ip_address}")
        file_path = download_file()
        print(f"📁 Fichier utilisé: {file_path}")
        data = analyze_pcap_and_ip(file_path, ip_address)
        return jsonify(data)
    except Exception as e:
        print("❌ Erreur /private_access:", traceback.format_exc())
        return jsonify({"error": str(e)}), 500


@app.route("/public_access/<ip_address>")
def public_access_route(ip_address):
    try:
        file_path = download_file()
        data = public_access(file_path, ip_address)
        return jsonify(data)
    except Exception as e:
        print("❌ Erreur /public_access:", traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route("/map")
def map_data():
    try:
        file_path = download_file()
        data = pcap_to_json(file_path)
        return jsonify(data)
    except Exception as e:
        import traceback
        print("🔥 Erreur /map :", e)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

def get_country_info_from_ip(ip):
    try:
        if ip.startswith("172."):
            return {"countryCode": "FR"}
        elif ip.startswith("91."):
            return {"countryCode": "DE"}
        elif ip.startswith("216."):
            return {"countryCode": "US"}
        elif ip.startswith("192.241."):
            return {"countryCode": "NL"}
        return {"countryCode": None}
    except:
        return {"countryCode": None}

@app.route("/map_malicious")
def map_malicious():
    suspicious_ips = get_ip_analysis()
    countries = {}
    for ip in suspicious_ips:
        info = get_country_info_from_ip(ip)  # À faire ou mock
        code = info.get("countryCode")
        if not code:
            countries.setdefault("inconnu", []).append(ip)
            continue
        countries.setdefault(code, []).append(ip)
    return jsonify(countries)

@app.route("/codeiso/<alpha2>")
def codeiso(alpha2):
    try:
        return jsonify(get_country_info(alpha2))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/threat_score/<ip>")
def threat_score_check(ip):
    try:
        return jsonify(threat_score(ip))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/map2")
def map2():
    try:
        file_path = download_file()
        map_generator(file_path)
        return jsonify({"message": "Map générée"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/suspicious")
def suspicious():
    try:
        data = get_ip_analysis()
        print("🕵️ Données analysées :", data)
        return jsonify(data)
    except Exception as e:
        print("❌ Erreur dans /suspicious :", e)
        return jsonify({"error": str(e)}), 500

from collections import Counter
import subprocess

def get_ip_analysis():
    try:
        print("🔍 get_ip_analysis() lancé")
        file_path = "./pcap/ex4.pcap"
        cmd = ["tshark", "-r", file_path, "-T", "fields", "-e", "ip.src", "-e", "ip.dst"]
        output = subprocess.check_output(cmd, text=True)

        counter = Counter()
        for line in output.splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                counter[parts[0]] += 1
                counter[parts[1]] += 1

        max_count = max(counter.values(), default=1)
        results = {}
        for ip, count in counter.items():
            if ip.startswith(("224.", "239.", "255.")) or ip == "":
                continue
            score = min(int((count / max_count) * 100), 100)
            if score > 30:  # Seuil
                results[ip] = {
                    "state": "malicious",
                    "threat_score": score
                }

        print("🕵️ Données analysées :", results)
        return results
    except Exception as e:
        print("⚠️ Erreur dans get_ip_analysis :", e)
        return {}

@app.route("/malware")
def malware():
    try:
        file_path = download_file()
        data = analyze_malware(file_path)
        return jsonify(data)
    except Exception as e:
        print("❌ Erreur /malware:", traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route("/malware/list")
def malware_list():
    try:
        file_path = download_file()
        data = parse_tshark_output(file_path)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/health")
def health():
    import shutil, os
    return {
        "status": "ok",
        "tshark_installed": shutil.which("tshark") is not None,
        "pcap_present": os.path.exists("pcap/ex4.pcap")
    }

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
