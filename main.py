import requests
from datetime import datetime
import urllib3

DEPENDENCY_TRACK_BASE_URLS = {
 ("https:// /api/v1/",""),
 ("https:// /api/v1/"," ")
}

DEPENDENCY_TRACK_BASE_URL = "https:// /api/v1/"
DEPENDENCY_TRACK_API_KEY = ""
WHITELIST_URI = "https://raw.githubusercontent.com/vmvarga/dtrack-whitelist/main/exclusions.json"


def read_wlist():

    r = requests.get(WHITELIST_URI)
    exclusions = r.json()

    return exclusions['exclusions']


def resolve_source(vulnid):
    idx = vulnid.split('-')[0]
    if idx == 'sonatype':
        source = 'OSSINDEX'
    elif idx == 'CVE':
        source = 'NVD'
    elif idx == 'GHSA':
        source = 'GITHUB'
    else:
        source = None
    return source


def findprojectuuid(comp, s, dtrackuri=DEPENDENCY_TRACK_BASE_URL):
    r = s.get(f'{dtrackuri}component/{comp}', verify=False)
    resp = r.json()
    projuuid = resp['project']['uuid']
    projname = f"{resp['project']['name']} {resp['project']['version']}"
    return projuuid, projname


def search_vuln(source, vulnid, s, purllist=None, dtrackuri=DEPENDENCY_TRACK_BASE_URL):
    if purllist is None:
        purllist = []
    r = s.get(f'{dtrackuri}vulnerability/source/{source}/vuln/{vulnid}', verify=False)
    if r.status_code == 404:
        return None

    resp = r.json()
    found = []
    vulnuuid = resp['uuid']
    vulnname = resp.get('title')
    if not vulnname:
        vulnname = resp.get('vulnId')

    if not resp.get('components'):
        return None

    for comp in resp['components']:
        prjuuid = comp['project'].get('uuid')
        prjname = f"{comp['project'].get('name')} {comp['project'].get('version')}"
        if not prjuuid:
            prjuuid, prjname = findprojectuuid(comp['uuid'], s, dtrackuri=dtrackuri)
        vulnobj = {
            'compuuid': comp['uuid'],
            'prjuuid': prjuuid,
            'vulnuuid': vulnuuid,
            'prjname': prjname,
            'vulnname': vulnname
        }

        if purllist and comp['purl'] in purllist:
            found.append(vulnobj)
        elif not purllist:
            found.append(vulnobj)
    return found


def suppress_vuln(vuln, s, comment=None, dtrackuri=DEPENDENCY_TRACK_BASE_URL):
    data = {
     "project": vuln['prjuuid'],
     "component": vuln['compuuid'],
     "vulnerability": vuln['vulnuuid'],
     "analysisState": "NOT_AFFECTED",
     "comment": f"DSeptic suppressed this for you more info appsecurity@ingrammicro.com. {comment}",
     "suppressed": "true"
    }
    headers = {"Content-Type": "application/json"}
    uri = f"{dtrackuri}analysis"
    r = s.put(uri, json=data, headers=headers, verify=False)
    return r.status_code


def is_suppressed(vuln, s, dtrackuri=DEPENDENCY_TRACK_BASE_URL):
    uri = f"{dtrackuri}analysis?component={vuln['compuuid']}&vulnerability={vuln['vulnuuid']}"
    r = s.get(uri, verify=False)
    if len(r.text) == 0:
        return False
    else:
        resp = r.json()
    flag = resp['isSuppressed']
    return flag


def is_suppressed_indb(vuln, db):
    if vuln['vulnuuid'] in db[vuln['compuuid']]:
        return True
    else:
        return False

def suppressvulnindtrackinstance(dtrackuri, apikey):
    count = 0
    for vulnerability in read_wlist():
        vulnid = vulnerability['vulnid']
        purllist = vulnerability.get('purl')
        source = resolve_source(vulnid)
        comment = vulnerability.get('comment')
        s = requests.Session()
        s.headers.update({'X-Api-Key': apikey})
        found = search_vuln(source, vulnid, s, purllist, dtrackuri=dtrackuri)
        if not found:
            continue

        for vuln in found:
            if is_suppressed(vuln, s, dtrackuri=dtrackuri):
                #print(f"[*] {vuln['vulnname']} in {vuln['prjname']} is already suppressed")
                continue
            status = suppress_vuln(vuln, s, comment, dtrackuri=dtrackuri)
            count += 1
            if status == 200:
                now = datetime.now()
                dt = now.strftime("%d/%m/%Y %H:%M:%S")
                print(f"[+] [{dt}] Suppressed {vuln['vulnname']} in {vuln['prjname']}")

    now = datetime.now()
    dt = now.strftime("%d/%m/%Y %H:%M:%S")
    print(f"[{dt}] Suppressed {count} vulnerabilities")


if __name__ == '__main__':
    urllib3.disable_warnings()
    for dtrackurikey in DEPENDENCY_TRACK_BASE_URLS:
        suppressvulnindtrackinstance(dtrackurikey[0], dtrackurikey[1])
