import json
import vt
import os
import time
from dotenv import load_dotenv

load_dotenv()

OUTFILE = 'ngrok-binaries.json'
VT_TIMEOUT = 15
VT_DAILY_MAX = 10
vt_call_counter = 0


def fetchReleasesFromFile():
    if os.path.exists(OUTFILE):
        with open(OUTFILE) as f:
            d = json.load(f)
            return d
    return []


def get_vt_code_signing_status(sha256):
    global vt_call_counter
    API_KEY = os.environ['VT_API']
    client = vt.Client(API_KEY)
    try:
        with vt.Client(API_KEY) as client:
            info = client.get_object("/files/"+sha256)
            print('incrementing counter')
            vt_call_counter += 1
            time.sleep(VT_TIMEOUT)
            return info.signature_info['verified']
    except Exception as err:
        vt_call_counter += 1
        print(err)
        return None


def insert_code_signing_status(binary_obj):
    global vt_call_counter
    platforms = list(binary_obj.values())[2]
    for platform in platforms:
        if vt_call_counter == VT_DAILY_MAX:
            print('call counter max reached')
            break
        sha256 = list(platform.values())[-1]
        css = get_vt_code_signing_status(sha256)
        if css is not None:
            platform['code_signing_status'] = css
    return platforms


binaries = fetchReleasesFromFile()
for binary in binaries:
    for attrs in binary['platforms']:
        if len(attrs) == 7:
            print(
                f"{attrs['archive_url']} already has code_signing_status, skipping")
            continue
    insert_code_signing_status(binary)

with open(OUTFILE, 'w') as filetowrite:
    filetowrite.write(json.dumps(binaries))
