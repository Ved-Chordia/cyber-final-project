
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

parser = argparse.ArgumentParser(description="Basic Web Vulnerability Scanner")
parser.add_argument("url", help="Target URL to scan")
args = parser.parse_args()
target_url = args.url

def get_forms(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(f"[!] Error fetching forms: {e}")
        return []

def get_form_details(form):
    details = {}
    action = form.get("action") or ""
    method = form.get("method", "get").lower()
    inputs = []
    for tag in form.find_all("input"):
        input_type = tag.get("type", "text")
        name = tag.get("name")
        if name:
            inputs.append({"type": input_type, "name": name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, payload):
    target = urljoin(url, form_details["action"])

    data = {}
    for input in form_details["inputs"]:
        if input["type"] == "text":
            data[input["name"]] = payload
        else:
            data[input["name"]] = "test"

    print(f"[*] Submitting payload to {target}")

    try:
        if form_details["method"] == "post":
            return requests.post(target, data=data, timeout=10)
        else:
            return requests.get(target, params=data, timeout=10)
    except Exception as e:
        print(f"[!] Request failed: {e}")
        return None

def is_vulnerable(response, payload):
    return response is not None and payload in response.text

payloads = ["<script>alert(1)</script>", "' OR '1'='1"]

print(f"\n[+] Scanning URL: {target_url}")
forms = get_forms(target_url)

if not forms:
    print("[!] No forms found.")
else:
    for i, form in enumerate(forms):
        form_details = get_form_details(form)
        for payload in payloads:
            res = submit_form(form_details, target_url, payload)
            if is_vulnerable(res, payload):
                print(f"[!!!] Vulnerability found in form #{i+1} with payload: {payload}")
            else:
                print(f"[-] No vuln detected with payload: {payload}")
