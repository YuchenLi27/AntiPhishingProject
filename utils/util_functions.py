# tools function that can be shared by any class, but logically not belong to any class. then we call util fun.
import csv
from urllib.parse import urlparse

from utils.constants import URL_LIST_SIZE

def get_hostname(url):
    if not url:
        return ""

    full_url = "https://{}"
    if not url.startswith("http://") and not url.startswith("https://"):
        full_url = full_url.format(url) #if we use requrest, we have to add protocol on, so we need line 11 and 13
    else:
        full_url = url

    full_url = full_url.strip()
    parse_result = urlparse(full_url) # help us decode  http/https:// to hostname, dns etc parts.
    return parse_result.hostname

def get_legitimate_url_list():
    legitimate_url_list = []
    with open("input_files/majestic_million.csv") as legitimate_urls:
        csv_reader = csv.DictReader(legitimate_urls, delimiter=",", quotechar='"')
        # delimiter help us to divide, quotechar helps us to escape " within the text.
        #Create an object which operates like a regular writer but maps dictionaries onto output rows.
        # The fieldnames parameter is a sequence of keys that identify the order in which values
        # in the dictionary passed to the writerow() method are written to file legitimate_urls.
        count = 1
        for row in csv_reader:
            url = row["Domian"].strip()
            legitimate_url_list.append(url)
            count += 1
            if count >= URL_LIST_SIZE:
                break
    return legitimate_url_list


def get_phishing_url_list():
    phishing_url_list = []
    with open("input_files/phishing_list_1.csv") as phishing_urls:
        for row in phishing_urls:
            row = row.strip()
            phishing_url_list.append(row)

    with open("input_files/phishing_list.txt") as phishing_urls:
        for row in phishing_urls:
            row = row.strip()
            phishing_url_list.append(row)

    with open("input_files/verified_online.csv") as phishing_urls:
        csv_reader = csv.DictReader(phishing_urls, delimiter=",", quotechar='"')
        for row in csv_reader:
            url = row["url"].strip()
            phishing_url_list.append(url)

    return phishing_url_list


def convert_url_to_filename(float_value):
    return str(format(float_value, ".3f"))



