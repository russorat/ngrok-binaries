import requests, sys
import hashlib
import tarfile, zipfile, io, glob, json, vt, os, time, datetime
from dotenv import load_dotenv


from bs4 import BeautifulSoup

load_dotenv()

OUTFILE = 'ngrok-binaries.json'

def download_and_hash(url):
    response = requests.get(url)
    response.raise_for_status()  # Raise an exception for bad status codes

    hasher = hashlib.sha256()
    for chunk in response.iter_content(chunk_size=8192):
        hasher.update(chunk)

    return hasher.hexdigest()

def download_and_untar_gz(url, destination):
    """Downloads and untars a .tar.gz file."""

    if os.path.exists(destination):
        print("{} already downloaded, skipping...".format(url))
        return

    # Download the file
    response = requests.get(url)
    response.raise_for_status()  # Raise an exception if download fails

    # Create a temporary file to store the downloaded content
    with open("temp.tar.gz", "wb") as f:
        f.write(response.content)

    # Extract the .tar.gz file
    with tarfile.open("temp.tar.gz", "r:gz") as tar:
        tar.extractall(destination)

def download_and_unzip(url, destination):
    """Downloads and unzips a .zip file."""

    if os.path.exists(destination):
        print("{} already downloaded, skipping...".format(url))
        return

    # Download the file
    response = requests.get(url)
    response.raise_for_status()  # Raise an exception if download fails

    z = zipfile.ZipFile(io.BytesIO(response.content))

    z.extractall(destination)

def sha256sum(filename):
    with open(filename, 'rb', buffering=0) as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()
    
def getVTScore(sha256):
    API_KEY = os.environ['VT_API']
    client = vt.Client(API_KEY)
    try:
        with vt.Client(API_KEY) as client:
            info = client.get_object("/files/"+sha256)
            time.sleep(15)
            return {
                'failure': info.last_analysis_stats['failure'], 
                'harmless': info.last_analysis_stats['harmless'], 
                'malicious': info.last_analysis_stats['malicious'], 
                'suspicious': info.last_analysis_stats['suspicious'], 
                'timeout': info.last_analysis_stats['timeout'],
                'type-unsupported': info.last_analysis_stats['type-unsupported'],
                'undetected': info.last_analysis_stats['undetected']
            }   
    except:
        return {}

def fetchReleaseDates():
    URL = "https://ngrok.com/docs/agent/changelog/"
    page = requests.get(URL)
    soup = BeautifulSoup(page.content, "html.parser")
    results = soup.find_all("h3", class_="anchor anchorWithStickyNavbar_GhIE")
    releases = {}
    for result in results:
        version = result.text.strip().split()[2]
        if version < '3':
            continue
        the_date = result.text.strip().split('[')[1].split(']')[0]
        if version >= '4':
            version = result.text.strip().split()[3]
            the_date = result.text.strip().split('[')[2].split(']')[0]
        releases[version] = the_date
    releases['3.14.1'] = '2024-08-22'
    releases['3.21.0'] = '2025-03-13'
    releases['3.0.0-rc1'] = ''
    return releases

def fetchReleasesFromFile():
    if os.path.exists(OUTFILE):
        with open(OUTFILE) as f:
            d = json.load(f)
            return d
    return []

release_dates = fetchReleaseDates()
print(release_dates)

URL = "https://dl.equinox.io/ngrok/ngrok-v3/stable/archive"
page = requests.get(URL)
soup = BeautifulSoup(page.content, "html.parser")
results = soup.find_all("div", class_="release")

binaries = fetchReleasesFromFile()
already_processed = {}
for binary in binaries:
    already_processed[binary['version']] = True

for result in results:
  release = {}
  version = result.find("h2").text.strip().split()[1]
  if version in already_processed:
      print("Version {} already processed. Skipping.".format(version))
      continue
  release["version"] = version
  release["release_date"] = release_dates[version]
  release["platforms"] = []
  archives = result.find_all("div", class_="platform archive")
  for archive in archives:
    links = archive.find_all("div", class_="link")
    for link in links:
      url = link.find("a", class_="btn download")["href"]
      dir = "binaries/"+url.split('/')[-1]
      if url.endswith('.tar.gz'):
         download_and_untar_gz(url,dir)
      if url.endswith('.zip'):
         download_and_unzip(url, dir)
      file_path = glob.glob(dir + "/*")[0]
      created_at = os.path.getmtime(file_path)
      if release["release_date"] == "":
          release["release_date"] = datetime.datetime.fromtimestamp(created_at).strftime('%Y-%m-%d')
      binary_sha256 = sha256sum(file_path)
      #binary_vt_score = getVTScore(binary_sha256)
      platform = url.split('-')[3]
      ending = link.find("div", class_="archive").text.strip()
      arch = link.find("div", class_="arch").text.strip()
      archive_sha256 = link.find("input")["value"]
      #archive_vt_score = getVTScore(archive_sha256)
      release["platforms"].append(
        {
            #"created_at": datetime.datetime.fromtimestamp(created_at).strftime('%Y-%m-%d %H:%M:%S'),
            "platform": platform,
            "arch": arch,
            "archive_url": url,
            "hash_type": "SHA256",
            "archive_hash": archive_sha256,
            "binary_hash": binary_sha256
            # ,"code_signing_status": ""
            # ,"archive_virustotal_score": archive_vt_score,
            # "binary_virustotal_score": binary_vt_score
        }
      )
  binaries.append(release)

print(json.dumps(binaries,indent=2))

with open(OUTFILE, 'w') as filetowrite:
    filetowrite.write(json.dumps(binaries,indent=2))
