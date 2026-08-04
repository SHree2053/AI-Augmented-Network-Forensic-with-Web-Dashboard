# here integrating with virus total 
import requests
from django.core.cache import cache

#using api key here
VT_API_KEY = '2ecf88b310d94b41f14de9a4b13dc779066ea71c585540a30791269c7994bcd0'
VT_IP_URL = 'https://www.virustotal.com/api/v3/ip_addresses/{}'
VT_HEADERS = {'x-apikey': VT_API_KEY}

# setting for timesout 
CACHE_TIMEOUT = 3600 * 24  # 24 hours

# checking ip of the virustotal
def check_ip(ip):
    """
    Check IP reputation via VirusTotal.
    Returns dict with: score, detection_ratio, risk, country, last_analysis_date.
    Uses Django cache to avoid repeated API calls.
    """
    cache_key = f'vt_ip_{ip}'
    cached = cache.get(cache_key)
    if cached:
        return cached
    
    if not VT_API_KEY or VT_API_KEY:
        # fallback if not API
        return {
            'score': 0,
            'detection_ratio': '0/0',
            'risk': 'Unknown',
            'country': 'Unknown',
            'last_analysis_date': None,
            'error': 'No API key'
        }
    #using execptions handleing 
    try:
        response = requests.get(VT_IP_URL.format(ip), headers=VT_HEADERS, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            undetected = stats.get('undetected', 0)
            total = malicious + suspicious + undetected
            if total == 0:
                total = 1  #avoids the values
            
            # identifying the risk
            if malicious > 5:
                risk = 'High'
            elif malicious > 0:
                risk = 'Medium'
            else:
                risk = 'Low'
            #storing the results
            result = {
                'score': malicious,
                'detection_ratio': f"{malicious}/{total}",
                'risk': risk,
                'country': attributes.get('country', 'Unknown'),
                'last_analysis_date': attributes.get('last_analysis_date'),
                'error': None
            }
            # caching the result
            cache.set(cache_key, result, CACHE_TIMEOUT)
            return result
        elif response.status_code == 429:  #too many requsts will be refused
            return {
                'score': 0,
                'detection_ratio': 'N/A',
                'risk': 'Unknown',
                'country': 'Unknown',
                'last_analysis_date': None,
                'error': 'Rate limited'
            }
        else:
            return {
                'score': 0,
                'detection_ratio': 'Error',
                'risk': 'Unknown',
                'country': 'Unknown',
                'last_analysis_date': None,
                'error': f'HTTP {response.status_code}'   #retunr actual http errror code
            }
    except Exception as e:
        return {
            'score': 0,
            'detection_ratio': 'Error',
            'risk': 'Unknown',
            'country': 'Unknown',
            'last_analysis_date': None,
            'error': str(e)
        }