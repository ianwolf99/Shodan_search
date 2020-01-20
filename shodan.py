#!usr/bin/python3

print("**********************************")
print("*_______***SHODAN****____________*")
print("*____*Authored by Ian_wolf99*____*")
print("**********************************")

#import the shodan module
import shodan
SHODAN_API_KEY = input("Enter the Shodan Api key:")
api = shodan.shodan(SHODAN_API_KEY)
hostname = input("Enter the hotname to query")

#lookup the host
host = api.host(hostname)
#print general information
print(" IP:%Organization:%Operating system" ,(host['ip_str'],host.get('org','n/a'),host.get('os','n/a')))

#print all the banners

for item in host['data']:
    print(
        """port:%s
        banner:%s""",(item['port'],item['data']))


#print vuln information
for item in host['vulns']:
    CVE = item.replace('!','')
    print("'vulns: %s' % item ")
    exploits = api.exploits.search(CVE)
    for item in exploits['matches']:
        if item.get('cve') [0] == CVE:
            print("item.get('description)")
