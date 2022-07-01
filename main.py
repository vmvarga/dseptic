import requests
from datetime import datetime

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


def findprojectuuid(comp, s):
    r = s.get(f'{DEPENDENCY_TRACK_BASE_URL}component/{comp}')
    resp = r.json()
    projuuid = resp['project']['uuid']
    projname = f"{resp['project']['name']} {resp['project']['version']}"
    return projuuid, projname


def search_vuln(source, vulnid, s, purllist=None):
    if purllist is None:
        purllist = []
    r = s.get(f'{DEPENDENCY_TRACK_BASE_URL}vulnerability/source/{source}/vuln/{vulnid}')
    resp = r.json()
    found = []
    vulnuuid = resp['uuid']
    vulnname = resp.get('title')
    if not vulnname:
        vulnname = resp.get('vulnId')

    for comp in resp['components']:
        prjuuid = comp['project'].get('uuid')
        prjname = f"{comp['project'].get('name')} {comp['project'].get('version')}"
        if not prjuuid:
            prjuuid, prjname = findprojectuuid(comp['uuid'], s)
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


def suppress_vuln(vuln, s, comment=None):
    data = {
     "project": vuln['prjuuid'],
     "component": vuln['compuuid'],
     "vulnerability": vuln['vulnuuid'],
     "analysisState": "NOT_AFFECTED",
     "comment": f"DSeptic suppressed this for you. {comment}",
     "suppressed": "true"
    }
    headers = {"Content-Type": "application/json"}
    uri = f"{DEPENDENCY_TRACK_BASE_URL}analysis"
    r = s.put(uri, json=data, headers=headers, verify=False)
    return r.status_code


def is_suppressed(vuln, s):
    uri = f"{DEPENDENCY_TRACK_BASE_URL}analysis?component={vuln['compuuid']}&vulnerability={vuln['vulnuuid']}"
    r = s.get(uri)
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


if __name__ == '__main__':
    count = 0
    for vulnerability in read_wlist():
        vulnid = vulnerability['vulnid']
        purllist = vulnerability.get('purl')
        source = resolve_source(vulnid)
        comment = vulnerability.get('comment')
        s = requests.Session()
        s.headers.update({'X-Api-Key': DEPENDENCY_TRACK_API_KEY})
        found = search_vuln(source, vulnid, s, purllist)

        for vuln in found:
            if is_suppressed(vuln, s):
                #print(f"[*] {vuln['vulnname']} in {vuln['prjname']} is already suppressed")
                continue
            status = suppress_vuln(vuln, s, comment)
            count += 1
            if status == 200:
                now = datetime.now()
                dt = now.strftime("%d/%m/%Y %H:%M:%S")
                print(f"[+] [{dt}] Suppressed {vuln['vulnname']} in {vuln['prjname']}")

    now = datetime.now()
    dt = now.strftime("%d/%m/%Y %H:%M:%S")
    print(f"[{dt}] Suppressed {count} vulnerabilities")
