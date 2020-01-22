import requests,re
import json,time

def checkvt(Tester):
    data = {
      'apikey': 'c058c032efb7be34fc8f130e8bcda4d12fe4d87a3f480993dfe37ff5f196cab7',
      'url': Tester
    }
    
    request = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=data)
    time.sleep(60)
    
    params = (
        ('apikey', '<VIRUSTOTAL_API_HERE>'),
        ('resource', Tester),
    )
    
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params).text
    if r'detected": true' in response:
        x=re.findall(r"\"(\w+)\": \{\"detected\": true, \"result\": \"(\w.+?)\"},",response)
        for i in x:
            print(i)
    else:
        print("\nURL is clean on VT")

def sucuri(URLxx):
    headers = {
        'authority': 'sitecheck.sucuri.net',
        'accept': 'application/json',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-mode': 'cors',
        'referer': 'https://sitecheck.sucuri.net/',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-US,en;q=0.9',
    }
    
    params = (
        ('scan', str(URLxx)),
        )
    responsesx = requests.get('https://sitecheck.sucuri.net/api/v3/', headers=headers, params=params)
    datasec =json.loads(responsesx.text)
    try:
        datasec['blacklists']
        print("\nThis vendors backlisted the URL")
        for i in range(0,len(datasec['blacklists'])):
            print(str(datasec['blacklists'][i]['vendor']))
    except Exception as e:
        print("No Backlistings seen On Sucuri SiteCheck")
    
def urlscanio(Tester):
    headers = {
        'Content-Type': 'application/json',
        'API-Key': '<URLSCAN.io API HERE>',
    }
    data = '{         "url":"'+str(Tester)+'", "public": "on",         "tags": ["phishing", "malicious"]       }'
    responseurl = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=data)
    dataurl = json.loads(responseurl.text)
    time.sleep(60)
    response2 = requests.get(dataurl.values()[3])
    data2=json.loads(response2.text)
    #if "ERR_NAME_RESOLUTION_FAILED" in xx:
     # print("UrlScanio was uable to Scan this website. Not Resolved or Taken Down / Invalid URL")
    #else:
    try:
      data2['page']['ip']
      Host = str(data2['page']['ip'])
      URLx=str(data2['page']['url'])
      print("Resolve to ip  " + str(Host) + " and final Effective URL " + str(URLx))
      #print("Resolve to ip" + str(Host))
      urlstags=[x.encode('UTF8') for x in data2['verdicts']['overall']['tags']]
      urlsscore=data2['verdicts']['overall']['score']
      print("\nUrlscan tags this as  "+str(urlstags)+" and Overall Score is  "+str(urlsscore)+"\n")
      checkvt(str(URLx))
      sucuri(str(URLx))
      #phish(str(URLx))
    except Exception as e:
      print("  Not able to resolve the URL  . Temporarily not available?")

def safb(Tester):
    KEY='<Google Safe Browsing API here>'
    from pysafebrowsing import SafeBrowsing
    s = SafeBrowsing(KEY)
    r = s.lookup_url(Tester)
    print("\nGoogle safe browsing " + str(r))

'''def phish(datap):
    url = 'https://checkurl.phishtank.com/checkurl/'
    postdata = {'url': datap, 'format': 'json', 'app_key': '<PISHTANK API HERE>'}
    r = requests.post(url, data=postdata)
    ph=json.loads(r.text)
    try:
        print("IS this URL a valid phish? "+str(ph['results']['valid']) +" and is this verdict verified? " +str(ph['results']['verified']))
    except Exception as Z:
        print("URL not in DB Currently")'''


cc=open("URLS.txt","r").readlines()
for line in cc:
    print(line)
    line=line.rstrip("\n")
    urlscanio(line)
    safb(line)
