import requests
from modules.config import USE_REMOTE_SERVER

def moyenne(tableau):
    return sum(tableau) / len(tableau) if tableau else 0

def get_data():
    try:
        response = requests.get("http://127.0.0.1:5000/init_access")
        response.raise_for_status()
        return response.json()  # <-- ça doit rester un dict
    except Exception as e:
        print("❌ Erreur dans get_data() :", e)
        return {}


def data_to_ip(data):
    if not data or "initial_access" not in data:
        raise ValueError("Clé 'initial_access' manquante dans la réponse")

    info_list = data["initial_access"]

    if isinstance(info_list, list) and len(info_list) > 0:
        return info_list[0].get("ip")  # 👈 On prend la première IP détectée
    else:
        raise ValueError("initial_access est vide ou mal formé")


def get_ip_analysis():
    info = get_data()
    if not info:
        print("🔥 Erreur dans get_ip_analysis : données invalides")
        return {}

    try:
        ip = data_to_ip(info)
    except Exception as e:
        print("🔥 Erreur dans get_ip_analysis :", e)
        return {}

    public_access_api = f"http://127.0.0.1:5000/public_access/{ip}"

    try:
        response = requests.get(public_access_api)
        response.raise_for_status()
        ip_data = response.json()
    except Exception as e:
        print(f"Erreur lors de la récupération des IPs : {e}")
        return {ip: {"state": "unknown", "threat_score": 0}}

    result_dict = {}
    for target_ip in ip_data:
        try:
            analysis_api = f"http://127.0.0.1:5000/threat_score/{target_ip}"
            response = requests.get(analysis_api)
            response.raise_for_status()
            results = response.json()

            if results:
                result_dict[target_ip] = {
                    "state": results[-1]["verdict"],
                    "threat_score": moyenne([r["threat_score"] for r in results])
                }
        except Exception as e:
            result_dict[target_ip] = {"state": "error", "threat_score": 0, "error": str(e)}

    return result_dict
