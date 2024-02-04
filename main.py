# Pre-requisites:
# * N_m3u8DL-RE and mp4decrypt in current directory
# * ffmpeg in PATH

# PIP Requirements:
# * protobuf
# * bs4
# * xmltodict
# * browser_cookie3
# * requests
# * pycryptodomex

import argparse
import requests
import subprocess
import os
from bs4 import BeautifulSoup
import json
import platform         # check for windows OS
import shutil           # check for ffmpeg in PATH, part of python std
import browser_cookie3  # cookies for premium accs
from cdm.wks import WvDecrypt, device_android_generic, PsshExtractor, KeyExtractor


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.3',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Cache-Control': 'no-cache',
}

license_url = "https://npo-drm-gateway.samgcloud.nepworldwide.nl/authentication"

if platform.system() == "Windows":
    windows_flag = True
else: 
    windows_flag = False


parser = argparse.ArgumentParser(description='PYWKS-NPO')
parser.add_argument('-url', dest='url', required=False, help='NPO Video URL')
parser.add_argument('-file', dest='file', required=False, help='File with NPO Video URLs, one per line')
args = parser.parse_args()


def parse_url_file(file_path):
    with open(file_path, 'r') as file:
        urls = [line.strip() for line in file]
    return urls

if args.file and args.url:
    print("ERR: Please specify just one argument.")
    print("-url:     input NPO video URL")
    print("-file:    input a file with NPO video URLS, one per line")
    exit()
elif args.file:
    urls = parse_url_file(args.file)
elif args.url:
    urls = [args.url]
else:
    print("ERR: Please input your URL.")
    print("-url:     input NPO video URL")
    print("-file:    input a file with NPO video URLS, one per line")
    exit()


def find_cookies():
    print("Are you an NPO Plus subscriber and logged in on your browser? (y/N)")
    userinput = input().lower()
    if not userinput or userinput != 'y':
        return

    cookies = browser_cookie3.load(domain_name='npo.nl')
    return cookies


def find_targetId(url):
    # Get HTML and extract productId
    response_targetId = requests.get(url)
    content = response_targetId.content

    try: 
        url_split = url.split("/")
        target_slug = url_split[7]
    except:
        print("URL invalid.")
        print("URL format: https://npo.nl/start/serie/wie-is-de-mol/seizoen-24/wie-is-de-mol_56/afspelen")
        print(f"Your URL: {url}")
        exit()

    soup = BeautifulSoup(content, 'html.parser')
    script_tag = soup.find('script', {'id': '__NEXT_DATA__'})

    if script_tag:
        script_content = script_tag.contents[0]
    else:
        print("Script tag not found.")
        print("Hint: Use the -token <token> argument to supply your own.")

    def search(data, target_slug):
        if isinstance(data, list):
            for item in data:
                result = search(item, target_slug)
                if result:
                    return result
        elif isinstance(data, dict):
            for key, value in data.items():
                if key == "slug" and value == target_slug:
                    return data.get("productId")
                else:
                    result = search(value, target_slug)
                    if result:
                        return result
        return None

    data_dict = json.loads(script_content)
    target_product_id = search(data_dict, target_slug)
    return target_product_id


def find_CSRF(targetId, plus_cookie):
    response_CSRF = requests.get('https://npo.nl/start/api/auth/session', headers=headers, cookies=plus_cookie)
    response_cookies = response_CSRF.cookies.get_dict()
    csrf = response_cookies["__Host-next-auth.csrf-token"]

    csrf_cookies = {
        '__Host-next-auth.csrf-token': csrf,
        '__Secure-next-auth.callback-url': 'https%3A%2F%2Fnpo.nl',
    }

    if not plus_cookie:
        plus_cookie = csrf_cookies
    
    json_productId = {
        'productId': targetId,
    }

    response_token = requests.post('https://npo.nl/start/api/domain/player-token', cookies=plus_cookie, headers=headers, json=json_productId)
    token = response_token.json()["token"]
    return token


def find_MPD(token, url, plus_cookie):
    headers['Authorization'] = token

    json_auth = {
        'profileName': 'dash',
        'drmType': 'widevine',
        'referrerUrl': url,
    }

    response = requests.post('https://prod.npoplayer.nl/stream-link', headers=headers, json=json_auth, cookies=plus_cookie)
    response_data = response.json()
    stream_data = response_data.get('stream', {})

    if stream_data.get('streamURL'):
        return stream_data
    else: 
        print("NO MPD URL - BAD TOKEN") 
        print(response_data)
        exit()


def find_PSSH(mpd):
    mpd_url = mpd.get('streamURL')

    response = requests.get(mpd_url, headers=headers)
    pssh_extractor = PsshExtractor(response.text)
    pssh_value = pssh_extractor.extract_pssh()
    return pssh_value, mpd_url


def find_key(mpd, pssh):
    headers_license = {
        'x-custom-data': mpd.get('drmToken'),
        'origin': 'https://start-player.npo.nl',
        'referer': 'https://start-player.npo.nl/',
    }

    cert_b64 = None
    key_extractor = KeyExtractor(pssh, cert_b64, license_url, headers_license)
    keys = key_extractor.get_keys()
    wvdecrypt = WvDecrypt(init_data_b64=pssh, cert_data_b64=cert_b64, device=device_android_generic)
    raw_challenge = wvdecrypt.get_challenge()
    data = raw_challenge
    for key in keys:
        if isinstance(key, list):
            if key:
                for key_str in key:
                    return key_str


def check_prereq():
    if windows_flag == True:
        prereq_filelist = ['mp4decrypt.exe', 'N_m3u8DL-RE.exe']
    else:
        prereq_filelist = ['mp4decrypt', 'N_m3u8DL-RE']

    for file in prereq_filelist:
        if not os.path.isfile(file):
            print(f"ERR: {file} not found!")
            print("Please check your directory and try again.")
            exit()
    if shutil.which("ffmpeg") is None:
        print("ffmpeg not found in PATH.")
        exit()


# create filename based on input URL -- tested with: https://npo.nl/start/serie/wie-is-de-mol/seizoen-24/wie-is-de-mol_56/afspelen
def create_filename(url):
    url_split = url.split("/")
    title_split = url_split[7].split("_")

    filename =  title_split[0] + "_" + url_split[6] + "_" + str(int(title_split[1])) + "_encrypted"
    filename_new = filename.replace("_encrypted", "")
    return filename, filename_new


# output: filename.m4a (audio) and filename.mp4 (video)
def download(mpd_url, filename):
    if windows_flag == True:
        subprocess.run(['N_m3u8DL-RE.exe', '--auto-select', '--no-log', '--save-name', filename, mpd_url], stdout=subprocess.DEVNULL)
    else:
        subprocess.run(['./N_m3u8DL-RE', '--auto-select', '--no-log', '--save-name', filename, mpd_url], stdout=subprocess.DEVNULL)


def decrypt(key, filename, filename_new):
    if windows_flag == True:
        subprocess.run(['mp4decrypt.exe', '--key', key, str(filename + ".mp4"), str(filename_new + "_video.mp4")], stdout=subprocess.DEVNULL)
        subprocess.run(['mp4decrypt.exe', '--key', key, str(filename + ".m4a"), str(filename_new + "_audio.m4a")], stdout=subprocess.DEVNULL)
    else:
        subprocess.run(['./mp4decrypt', '--key', key, str(filename + ".mp4"), str(filename_new + "_video.mp4")], stdout=subprocess.DEVNULL)
        subprocess.run(['./mp4decrypt', '--key', key, str(filename + ".m4a"), str(filename_new + "_audio.m4a")], stdout=subprocess.DEVNULL)


def merge(filename_new):
    ffmpeg_command = [
        'ffmpeg', '-v', 'quiet', # '-stats',
        '-i', filename_new + "_video.mp4",
        '-i', filename_new + "_audio.m4a",
        '-c:v', 'copy',
        '-c:a', 'copy',
        '-strict', 'experimental',
        filename_new + ".mp4"   
    ]
    
    subprocess.run(ffmpeg_command)


def clean(filename_new):
        os.remove(filename + ".mp4")
        os.remove(filename + ".m4a")
        os.remove(filename_new + "_audio.m4a")
        os.remove(filename_new + "_video.mp4") 


def check_file(filename_new):
    if os.path.exists(filename_new + ".mp4"):
        print("Download successful!")
    else:
        print("File not found. Continue anyway? (y/N)")
        userinput = input().lower()
        if not userinput or userinput != 'y':
            exit()


plus_cookie = find_cookies()

for index, url in enumerate(urls):
    if len(urls) > 1:
        print("\n")
        print(f"Video {index+1}:")
    
    print("Fetching data...")
    productId = find_targetId(url)
    token = find_CSRF(productId,plus_cookie)
    mpd = find_MPD(token, url, plus_cookie)
    pssh, mpd_url = find_PSSH(mpd)
    key = find_key(mpd, pssh)
    check_prereq()
    filename, filename_new = create_filename(url)
    print("Downloading...")
    download(mpd_url, filename)
    print("Decrypting...")
    decrypt(key, filename, filename_new)
    print("Merging...")
    merge(filename_new)
    print("Cleaning up temporary files...")
    clean(filename_new)
    check_file(filename_new)




#########
# NOTES #
#########
# The downloader *should* work across every platform, linux/mac/win. 
# It has not been extensively tested on anything but windows.

# Supported browsers for NPO Plus cookies:
# (https://github.com/borisbabic/browser_cookie3#testing-dates--ddmmyy)
# * Chrome
# * Firefox
# * LibreWolf
# * Opera
# * Opera GX
# * Edge
# * Chromium
# * Brave
# * Vivaldi
# * Safari
