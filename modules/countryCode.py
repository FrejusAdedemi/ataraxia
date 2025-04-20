import json

def get_country_info(alpha2_code, file_path="countryCode.json"):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
            
            for country in data.get("ref_country_codes", []):
                if country.get("alpha2") == alpha2_code.upper():
                    return country
                elif country.get("alpha3") == alpha2_code.upper():
                    return country
            return None  # Retourne None si le pays n'est pas trouvé
    except Exception as e:
        print(f"Erreur : {e}")
        return None  # Retourne None en cas d'erreur

def format_json(object_json):
    response = []
    for iso in object_json:
        print(iso)
        country_info = get_country_info(iso)
        print(country_info)  # Enlever les espaces autour du code ISO

        if country_info == None:  # Si le pays est inconnu
            response.append({
                "country": "inconnu",
                "iso": "XX",
                "ip": object_json[iso] # Renvoyer tout le tableau d'IP
            })
        else:
            country_data = {
                "country": country_info.get("country", "Inconnu"),
                "latitude": country_info.get("latitude", "Inconnu"),
                "longitude": country_info.get("longitude", "Inconnu")
            }
            response.append(country_data)

    return {"data": response}