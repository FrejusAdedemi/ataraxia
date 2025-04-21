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

# @app.route("/codeiso/<code>")
# def get_country_latlng(code):
#     try:
#         response = requests.get(f"https://restcountries.com/v3.1/alpha/{code}")
#         response.raise_for_status()
#         data = response.json()
#
#         latlng = data[0].get("latlng", [0, 0])
#         return jsonify({"latlng": latlng})
#
#     except Exception as e:
#         print(f"❌ Erreur API pays pour {code} :", e)
#         return jsonify({"error": str(e), "latlng": [0, 0]}), 500

@app.route("/suspicious")
def suspicious():
    try:
        data = get_ip_analysis()
        print("🚨 Suspicious data :", data)  # 👈 Ajoute ce log temporaire
        return jsonify(data)
    except Exception as e:
        print("❌ Erreur /suspicious:", traceback.format_exc())
        return jsonify({"error": str(e)}), 500


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
