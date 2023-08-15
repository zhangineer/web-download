import os
import requests
from bs4 import BeautifulSoup
import urllib3
import re
from zipfile import ZipFile
import os

urllib3.disable_warnings()

INDEX_LINK_PATTERN = re.compile(r'^\d{2}/\d{2}/index\.html$')


def get_all_index_links(url):
    response = requests.get(url, verify=False)
    soup = BeautifulSoup(response.text, 'html.parser')
    links = [a['href'] for a in soup.find_all('a', href=True) if INDEX_LINK_PATTERN.match(a['href'])]
    return links


def get_all_pcap_zip_links(url):
    response = requests.get(url, verify=False)
    soup = BeautifulSoup(response.text, 'html.parser')

    # find all links with .pcap.zip extension
    links = [a['href'].strip() for a in soup.find_all('a', href=True) if 'pcap.zip' in a['href'] or 'pcaps.zip' in a['href']]
    if not links:
        print(f"no pcap file found for url {url}")
    return list(set(links))


def download_file(url, destination_folder):
    local_filename = os.path.join(destination_folder, url.split('/')[-1])

    with requests.get(url, stream=True, verify=False) as response:
        response.raise_for_status()
        with open(local_filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

    return local_filename


def main():
    DESTINATION_FOLDER = 'malware-traffic-analysis'
    os.makedirs(DESTINATION_FOLDER, exist_ok=True)

    for year in range(2017,2024):
        print("processing year: ", year)
        BASE_URL = f'https://www.malware-traffic-analysis.net/{year}'  # replace with your base URL

        # First, get all the index.html links from the base page
        index_links = get_all_index_links(BASE_URL)
        index_links = list(set(index_links))
        for index_link in index_links:
            # Construct full URL for each index link
            index_url = os.path.join(BASE_URL, index_link)
            # For each index.html page, get the pcap.zip file links
            pcap_zip_links = get_all_pcap_zip_links(index_url)
            if pcap_zip_links:
                for link in pcap_zip_links:
                    file_url = os.path.join(BASE_URL, index_link.strip("/index.html"), link)
                    try:
                        downloaded_file = download_file(file_url, DESTINATION_FOLDER)
                        print(f"Downloaded: {downloaded_file}")
                    except requests.exceptions.HTTPError as error:
                        print(error)
                        continue


def unzip(file_path):
    with ZipFile(file_path, "r") as zobject:
        print(file_path)
        zobject.extractall(path="malware-traffic-analysis-pcaps",pwd=b'infected')


if __name__ == '__main__':
    directory_path = 'malware-traffic-analysis'
    for filename in os.listdir(directory_path):
        if os.path.isfile(os.path.join(directory_path, filename)):
            try:
                unzip(os.path.join(directory_path, filename))
            except RuntimeError as e:
                print("Error !! ", e)

