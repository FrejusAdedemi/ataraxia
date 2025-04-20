from flask import Flask, jsonify,render_template
from flask_cors import CORS
from modules.return_file import download_file
from modules.initial_acces_service import envoyer_donnees_pcap, extract_pcap_info
from modules.ip_private_connections import analyze_pcap_and_ip
import json
from loguru import logger
from modules.certificate_detection import pcap_to_json
from modules.countryCode import get_country_info, format_json
from modules.check_ip import threat_score
from modules.map_api import map_generator
from modules.ip_connections import public_access
from modules.ip_public_analyze import  get_ip_analysis
from modules.appli_request import analyze_malware, parse_tshark_output
from flask import Flask, jsonify
from modules.return_file import download_file
from modules.map_generator import extract_ip_info
from modules.initial_acces_service import envoyer_donnees_pcap
from modules.config import USE_REMOTE_SERVER

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route('/file', methods=['GET'])
def get_data():
    file_path: str = download_file()
    return jsonify({"message": file_path})

@app.route("/init_access")
def initial_access():
    try:
        pcap_file = download_file()
        data = extract_pcap_info(pcap_file)

        # ✅ Si data est une string (ex: JSON brut), on le parse
        if isinstance(data, str):
            data = json.loads(data)

        return jsonify({
            "initial_access": data,
            "message": "Accès initial détecté"
        })
    except Exception as e:
        print("Erreur init_access:", e)
        return jsonify({"error": str(e)}), 500


@app.route('/private_access/<ip_address>', methods=['GET'])
def get_info(ip_address):
    file_path: str = download_file()
    data = analyze_pcap_and_ip(file_path, ip_address)
    return jsonify(data)

@app.route('/public_access/<ip_address>', methods=['GET'])
def get_public_info(ip_address):
    file_path: str = download_file()
    data = public_access(file_path, ip_address)
    return jsonify(data)

@app.route('/map', methods=['GET'])
def map_service():
    file_path: str = download_file()
    response = pcap_to_json(file_path)
    response = format_json(response)
    return jsonify(response)

@app.route('/codeiso/<alpha2>', methods=['GET'])
def iso_service(alpha2):
    response = get_country_info(alpha2)
    return jsonify(response)

@app.route('/threat_score/<ip>', methods=['GET'])
def check_threat_score(ip):
    response = threat_score(ip)
    return jsonify(response)

@app.route('/map2', methods=['GET'])
def map2_service():
    file_path: str = download_file()
    map_generator(file_path)
    return jsonify({"message": "test"})

@app.route('/suspicious', methods=['GET'])
def suspicious_service():
    try:
        data = get_ip_analysis()
        return jsonify(data)
    except Exception as e:
        import traceback
        print("Erreur suspicious:", traceback.format_exc())
        return jsonify({"error": str(e)}), 500


@app.route('/malware', methods=['GET'])
def malware_service():
    try:
        file_path: str = download_file()
        data = analyze_malware(file_path)
        return jsonify(data)
    except Exception as e:
        import traceback
        print("Erreur malware:", traceback.format_exc())
        return jsonify({"error": str(e)}), 500


@app.route('/malware/list', methods=['GET'])
def malware_list_service():
    file_path: str = download_file()
    data = parse_tshark_output(file_path)
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True)