import requests
import json

def threat_score(ip: str):
    url = 'https://hybrid-analysis.com/api/v2/search/terms'
    headers = {
        'accept': 'application/json',
        'api-key': 'eagd00t4105aa126yw0g1r40153697cejcgip5rq9089202a8utzjzkp0c8105e0',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'port': '',
        'imp_hash': '',
        'vx_family': '',
        'domain': '',
        'filename': '',
        'host': ip,
        'uses_tactic': '',
        'date_to': '',
        'ssdeep': '',
        'env_id': '',
        'av_detect': '',
        'similar_to': '',
        'url': '',
        'context': '',
        'authentihash': '',
        'filetype': '',
        'country': '',
        'verdict': '',
        'filetype_desc': '',
        'tag': '',
        'date_from': '',
        'uses_technique': ''
    }

    response = requests.post(url, headers=headers, data=data)
    response_data = response.json()

    malicious_results = [result for result in response_data['result'] if result['verdict'] == 'malicious']

    return malicious_results

