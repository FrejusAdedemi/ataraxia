import json

def get_country_info(code):
    with open("countryCode.json", encoding="utf-8") as f:
        data = json.load(f)

    for entry in data["ref_country_codes"]:
        if entry["alpha2"].upper() == code.upper():
            return {
                "latlng": [entry["latitude"], entry["longitude"]],
                "country": entry["country"]
            }

    return {
        "latlng": [0, 0],
        "country": "Inconnu"
    }


def format_json(object_json):
    response = []
    for iso in object_json:
        print(iso)
        country_info = get_country_info(iso)
        print(country_info)

        if country_info is None:
            response.append({
                "country": "inconnu",
                "iso": "XX",
                "ip": object_json[iso]
            })
        else:
            lat, lon = country_info.get("latlng", [0, 0])
            country_data = {
                "country": country_info.get("country", "Inconnu"),
                "latitude": lat,
                "longitude": lon,
                "ip": object_json[iso]  # 👈 Ajout des IPs ici
            }
            response.append(country_data)

    return {"data": response}
