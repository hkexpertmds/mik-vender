import os
import re
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from supabase import create_client, Client
from werkzeug.security import generate_password_hash, check_password_hash
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
import datetime
import json
import jwt
from functools import wraps

load_dotenv()

app = Flask(__name__)
CORS(app)

# ---------------------------------------------------------
# Supabase Setup (Aapko yahan apni keys daalni padengi)
# ---------------------------------------------------------
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Missing Supabase URL or Key. Please set them in the .env file.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

JWT_SECRET = os.environ.get("JWT_SECRET", "super-secret-vender-key-2024")

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            parts = request.headers['Authorization'].split()
            if len(parts) == 2 and parts[0] == 'Bearer':
                token = parts[1]
        if not token:
            return jsonify({'success': False, 'message': 'JWT Token is missing! Access Denied.'}), 401
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            request.user_data = data
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'message': 'Token has expired! Please log in again.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'message': 'Token is invalid!'}), 401
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------
# ALPHANUMERIC ID GENERATOR ALGORITHM (Base-36 0-9 & A-Z)
# ---------------------------------------------------------
def get_alphanumeric_sequence(index, length):
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    result = ""
    for _ in range(length):
        result = chars[index % 36] + result
        index //= 36
    return result

# ---------------------------------------------------------
# ADMIN INIT (Pehli baar login ke liye)
# ---------------------------------------------------------
def ensure_admin():
    try:
        admin_res = supabase.table('sys_users').select('id').eq('login_id', 'ADMIN').execute()
        if not admin_res.data:
            hashed_password = generate_password_hash('123')
            supabase.table('sys_users').insert({
                'name': 'Admin', 'login_id': 'ADMIN', 'pass': hashed_password,
                'type': 'Admin', 'company': 'SuperAdmin'
            }).execute()
            print("Default Admin account created successfully!")
    except Exception as e:
        print("Please ensure your tables are created in Supabase. Error:", e)

# ---------------------------------------------------------
# API ROUTES
# ---------------------------------------------------------

# Serve Frontend HTML Directly
@app.route('/')
@app.route('/index.html')
def serve_html():
    res = send_file('index.html')
    res.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return res

@app.route('/favicon.ico')
def favicon():
    return '', 204

# Registration API for Owner
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    district_val = data.get('district') or data.get('city') or '00'
    district_code = str(district_val).upper()[:2].ljust(2, '0')
    
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({"success": False, "message": "Unique Username is required!"})

    # --- UNIQUE VALIDATION ---
    mobile = (data.get('mobile') or '').strip() if data.get('mobile') else None
    email = (data.get('email') or '').strip() if data.get('email') else None
    if mobile:
        if supabase.table('sys_users').select('id').eq('type', 'Owner').eq('mobile', mobile).execute().data:
            return jsonify({"success": False, "message": "This mobile number is already registered as an Owner!"})
    if email:
        if supabase.table('sys_users').select('id').eq('type', 'Owner').eq('email', email).execute().data:
            return jsonify({"success": False, "message": "This email is already registered as an Owner!"})
    # -------------------------
    
    # Check username global uniqueness
    if supabase.table('sys_users').select('id').ilike('username', username).execute().data or supabase.table('sys_customers').select('id').ilike('username', username).execute().data:
        return jsonify({"success": False, "message": "This Username is already taken! Please try another."})

    # Auto Generate Owner ID
    res = supabase.table('sys_users').select('login_id').eq('type', 'Owner').ilike('login_id', f'{district_code}%').order('id', desc=True).limit(1).execute()
    next_index = 0
    if res.data and res.data[0].get('login_id'):
        last_id = res.data[0]['login_id']
        seq_str = last_id[len(district_code):]
        try:
            next_index = int(seq_str, 36) + 1
        except ValueError:
            pass
    new_owner_id = f"{district_code}{get_alphanumeric_sequence(next_index, 3)}"

    raw_pass = data.get('pass')
    if not raw_pass:
        return jsonify({"success": False, "message": "Password is required!"})

    hashed_pass = generate_password_hash(raw_pass)
    
    insert_data = {
        "name": data['name'],
        "login_id": new_owner_id,
        "username": username,
        "pass": hashed_pass,
        "type": "Owner",
        "company": data['company'],
        "email": data.get('email', ''),
        "address": data.get('address', ''),
        "mobile": data.get('mobile', ''),
        "license_expiry": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=15)).isoformat(),
        "ref_code": data.get('ref_code', '')
    }
    
    try:
        supabase.table('sys_users').insert(insert_data).execute()
        return jsonify({"success": True, "login_id": new_owner_id})
    except Exception as e:
        return jsonify({"success": False, "message": f"Database Error: {str(e)}"})


# Secure Login & Data Partitioning with Supabase
@app.route('/api/login', methods=['POST'])
def login():
    creds = request.json
    role = creds.get('role')
    login_id = (creds.get('login_id') or '').strip()
    password = creds.get('pass', '')
    
    if not login_id:
        return jsonify({"success": False, "message": "Please enter Login ID, Mobile or Username"})

    table = 'sys_customers' if role == 'Customer' else 'sys_users'
    id_field = 'cid' if role == 'Customer' else 'login_id'

    try:
        res = supabase.table(table).select('*').ilike(id_field, login_id).execute()
        user = res.data[0] if res.data else None
        
        if not user:
            res = supabase.table(table).select('*').ilike('username', login_id).execute()
            user = res.data[0] if res.data else None
            
        if not user:
            res = supabase.table(table).select('*').eq('mobile', login_id).execute()
            user = res.data[0] if res.data else None
            
        if not user and role != 'Customer':
            res = supabase.table(table).select('*').ilike('email', login_id).execute()
            user = res.data[0] if res.data else None
    except Exception as e:
        print("Login DB Error:", e)
        user = None

    if not user:
        return jsonify({"success": False, "message": "Wrong ID or Password"})

    pass_db = user.get('cpass', '') if role == 'Customer' else user.get('pass', '')
    is_valid = False
    if pass_db:
        try: is_valid = check_password_hash(pass_db, password)
        except Exception: pass
    if not is_valid:
        return jsonify({"success": False, "message": "Wrong ID or Password"})

    # Strict Role Validation (Prevent cross-role logins)
    if role != 'Customer':
        db_role = user.get('type')
        if role == 'Owner' and db_role not in ['Owner', 'Admin']:
            return jsonify({"success": False, "message": f"Account exists, but you are not registered as an {role}. Please select the correct portal!"})
        if role == 'Milk Man' and db_role != 'Milk Man':
            return jsonify({"success": False, "message": f"Account exists, but you are not registered as a {role}. Please select the correct portal!"})
        if role == 'Manager' and db_role != 'Manager':
            return jsonify({"success": False, "message": f"Account exists, but you are not registered as a {role}. Please select the correct portal!"})

    company = user.get('company', '')

    user_to_return = user.copy()

    # --- PYTHON FIX: INJECT OWNER'S LICENSE EXPIRY FOR ALL STAFF/CUSTOMERS ---
    if role != 'Admin' and company != 'SuperAdmin':
        if role != 'Owner':
            owner_res = supabase.table('sys_users').select('license_expiry').eq('type', 'Owner').ilike('company', company).execute()
            if owner_res and owner_res.data:
                user_to_return['license_expiry'] = owner_res.data[0].get('license_expiry')
            else:
                fallback = supabase.table('sys_users').select('license_expiry').eq('type', 'Owner').execute()
                if fallback and fallback.data:
                    user_to_return['license_expiry'] = fallback.data[0].get('license_expiry')
    # --------------------------------------------------------------------------

    if role == 'Customer':
        user_to_return['type'] = 'Customer'
        user_to_return['login_id'] = user_to_return.get('cid')
        
        # Fetch Owner's QR code so it shows correctly on frontend payment page
        try:
            owner_res = supabase.table('sys_users').select('qr_code, company_logo').eq('type', 'Owner').eq('company', company).execute()
            if owner_res.data:
                user_to_return['owner_qr'] = owner_res.data[0].get('qr_code', '')
                user_to_return['owner_logo'] = owner_res.data[0].get('company_logo', '')
        except Exception:
            pass
        
    if 'pass' in user_to_return:
        del user_to_return['pass']
    if 'cpass' in user_to_return:
        del user_to_return['cpass']
        
    token = jwt.encode({
        'login_id': user_to_return.get('login_id', user_to_return.get('cid')),
        'role': role,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
    }, JWT_SECRET, algorithm="HS256")

    return jsonify({"success": True, "user": user_to_return, "token": token})
        
@app.route('/api/sync_data', methods=['POST'])
@token_required
def sync_data():
    req_data = request.json
    role = req_data.get('role')
    login_id = req_data.get('login_id')
    company = req_data.get('company')
    name = req_data.get('name')
    
    # --- PYTHON LEVEL SECURITY ENFORCEMENT ---
    # 1. Authoritative Company Fetch (prevents frontend spoofing)
    if role in ['Owner', 'Admin', 'Manager', 'Milk Man']:
        user_details_res = supabase.table('sys_users').select('company').eq('login_id', login_id).execute()
        if not user_details_res.data:
            return jsonify({"success": False, "message": "Could not verify user."}), 403
        company = user_details_res.data[0].get('company')
    elif role == 'Customer':
        
        cust_details_res = supabase.table('sys_customers').select('company').eq('cid', login_id).execute()
        if not cust_details_res.data:
            return jsonify({"success": False, "message": "Could not verify customer."}), 403
        company = cust_details_res.data[0].get('company')

    # 2. Global License Enforcement for ALL Roles
    if role != 'Admin' and company != 'SuperAdmin':
        expiry_str = None
        if role == 'Owner':
            owner_res = supabase.table('sys_users').select('license_expiry').eq('login_id', login_id).execute()
            if owner_res and owner_res.data:
                expiry_str = owner_res.data[0].get('license_expiry')
        else:
            owner_res = supabase.table('sys_users').select('license_expiry').eq('type', 'Owner').ilike('company', company).execute()
            if owner_res and owner_res.data:
                expiry_str = owner_res.data[0].get('license_expiry')

        if expiry_str:
            try:
                expiry_date = datetime.datetime.fromisoformat(expiry_str.replace('Z', '+00:00'))
                if expiry_date.tzinfo is None:
                    expiry_date = expiry_date.replace(tzinfo=datetime.timezone.utc)
                
                grace_period_end = expiry_date + datetime.timedelta(days=7)
                if datetime.datetime.now(datetime.timezone.utc) > grace_period_end:
                    # WIPE OUT ALL DATA IF EXPIRED (Returns empty lists to frontend to clear cache)
                    return jsonify({
                        "success": True, 
                        "message": "License expired. Data wiped from device.",
                        "data": {"users": [], "customers": [], "transactions": [], "products": [], "requests": [], "routes": [], "licenses": []}
                    })
            except (ValueError, TypeError):
                pass
    # ------------------------------------------

    # 🚀 DB FIX: Use '*' to prevent backend crashes if new columns are missing in Supabase.
    u_cols = '*'
    c_cols = '*'

    def safe_get(f):
        try:
            return f.result()
        except Exception as e:
            print("Sync Error:", e)
            return []

    if role in ['Owner', 'Admin', 'Manager']:
        with ThreadPoolExecutor(max_workers=7) as executor:
            if role == 'Admin' or company == 'SuperAdmin':
                f_u = executor.submit(lambda: supabase.table('sys_users').select(u_cols).execute().data)
                f_c = executor.submit(lambda: supabase.table('sys_customers').select(c_cols).execute().data)
                f_t = executor.submit(lambda: supabase.table('sys_trans').select('*').order('id', desc=True).limit(300).execute().data)
                f_p = executor.submit(lambda: supabase.table('sys_products').select('*').execute().data)
                f_r = executor.submit(lambda: supabase.table('sys_requests').select('*').order('id', desc=True).limit(20).execute().data)
                f_ro = executor.submit(lambda: supabase.table('sys_routes').select('*').execute().data)
                f_l = executor.submit(lambda: supabase.table('sys_licenses').select('*').execute().data)
            else:
                f_u = executor.submit(lambda: supabase.table('sys_users').select(u_cols).eq('company', company).execute().data)
                f_c = executor.submit(lambda: supabase.table('sys_customers').select(c_cols).eq('company', company).execute().data)
                f_t = executor.submit(lambda: supabase.table('sys_trans').select('*').eq('company', company).order('id', desc=True).limit(300).execute().data)
                f_p = executor.submit(lambda: supabase.table('sys_products').select('*').eq('company', company).execute().data)
                f_r = executor.submit(lambda: supabase.table('sys_requests').select('*').eq('company', company).order('id', desc=True).limit(20).execute().data)
                f_ro = executor.submit(lambda: supabase.table('sys_routes').select('*').eq('company', company).execute().data)
                f_l = executor.submit(lambda: supabase.table('sys_licenses').select('*').eq('used_by', login_id).execute().data)
        
        users = safe_get(f_u)
        customers = safe_get(f_c)
        transactions = safe_get(f_t)
        products = safe_get(f_p)
        requests = safe_get(f_r)
        routes = safe_get(f_ro)
        licenses = safe_get(f_l)
        
        if role == 'Manager':
            filtered_t = []
            for t in transactions:
                if t.get('shift') == 'General Bill':
                    created_by = t.get('cust')
                    qty_str = t.get('qty', '')
                    if qty_str and qty_str.startswith('{'):
                        try:
                            qty_data = json.loads(qty_str)
                            created_by = qty_data.get('created_by', created_by)
                        except Exception:
                            pass
                    if created_by == login_id:
                        filtered_t.append(t)
                else:
                    filtered_t.append(t)
            transactions = filtered_t
            customers, requests, routes, licenses = [], [], [], []

        if role == 'Admin' or company == 'SuperAdmin':
            user_map = {user['login_id']: user for user in users}
            for lic in licenses:
                if lic.get('used_by') in user_map:
                    user_info = user_map[lic['used_by']]
                    lic['used_by_name'] = user_info.get('name')
                    lic['used_by_company'] = user_info.get('company')

        return jsonify({"success": True, "data": {"users": users, "customers": customers, "transactions": transactions, "products": products, "requests": requests, "routes": routes, "licenses": licenses}})
        
    elif role == 'Milk Man':
        milkman_customers_res = supabase.table('sys_customers').select(c_cols).eq('company', company).eq('milkman_id', login_id).execute()
        milkman_customers = milkman_customers_res.data if milkman_customers_res.data else []
        
        if milkman_customers:
            for c in milkman_customers:
                c.pop('cpass', None)
                
        customer_names = [c['name'] for c in milkman_customers]
        customer_ids = [c['cid'] for c in milkman_customers]

        def get_mm_trans():
            if not customer_names: return []
            lower_names = [n.strip().lower() for n in customer_names if n]
            all_trans = supabase.table('sys_trans').select('*').eq('company', company).order('id', desc=True).limit(1000).execute().data
            return [t for t in all_trans if (t.get('cust') or '').strip().lower() in lower_names][:150]

        with ThreadPoolExecutor(max_workers=4) as executor:
            f_t = executor.submit(get_mm_trans)
            f_p = executor.submit(lambda: supabase.table('sys_products').select('*').eq('company', company).execute().data)
            
            def get_mm_requests():
                if not customer_ids: return []
                str_ids = [str(cid).strip().lower() for cid in customer_ids if cid]
                all_reqs = supabase.table('sys_requests').select('*').eq('company', company).order('id', desc=True).limit(500).execute().data
                return [r for r in all_reqs if str(r.get('cust_id') or '').strip().lower() in str_ids][:50]
                
            f_r = executor.submit(get_mm_requests)
            f_ro = executor.submit(lambda: supabase.table('sys_routes').select('*').eq('company', company).execute().data)
            
        try: milkman_trans = f_t.result()
        except Exception: milkman_trans = []
        
        return jsonify({"success": True, "data": {"users": [], "customers": milkman_customers, "transactions": milkman_trans, "products": safe_get(f_p), "requests": safe_get(f_r), "routes": safe_get(f_ro), "licenses": []}})
        
    elif role == 'Customer':
        with ThreadPoolExecutor(max_workers=5) as executor:
            f_t = executor.submit(lambda: supabase.table('sys_trans').select('*').eq('cust', name).eq('company', company).order('id', desc=True).limit(100).execute().data)
            f_p = executor.submit(lambda: supabase.table('sys_products').select('*').eq('company', company).execute().data)
            f_r = executor.submit(lambda: supabase.table('sys_requests').select('*').eq('cust_id', login_id).eq('company', company).order('id', desc=True).limit(15).execute().data)
            f_ro = executor.submit(lambda: supabase.table('sys_routes').select('*').eq('company', company).execute().data)
            f_u = executor.submit(lambda: supabase.table('sys_users').select('*').in_('type', ['Owner', 'Milk Man', 'Manager']).eq('company', company).execute().data)
        
        owner_users = safe_get(f_u)
        if owner_users:
            for u in owner_users:
                u.pop('pass', None)
        owner_qr = owner_users[0].get('qr_code', '') if owner_users else ''
        return jsonify({"success": True, "data": {"users": owner_users, "customers": [], "transactions": safe_get(f_t), "products": safe_get(f_p), "requests": safe_get(f_r), "routes": safe_get(f_ro), "licenses": [], "owner_qr": owner_qr}})
    return jsonify({"success": False})


# Data Save/Update APIs (Generic Route)
@app.route('/api/<table_name>', methods=['POST'])
@token_required
def save_data(table_name):
    data = request.json
    
    if table_name not in ['users', 'customers', 'transactions', 'products', 'requests', 'routes', 'licenses']:
        return jsonify({"success": False, "message": "Invalid table"}), 400
        
    db_table = 'sys_' + (table_name if table_name != 'transactions' else 'trans')

    # --- UNIQUE VALIDATION FOR MOBILE & EMAIL ---
    item_id_val = data.get('id')
    mobile = (data.get('mobile') or '').strip() if data.get('mobile') else None
    email = (data.get('email') or '').strip() if data.get('email') else None
    
    if table_name == 'users':
        username = (data.get('username') or '').strip()
        user_type = data.get('type')
        
        if username:
            q = supabase.table('sys_users').select('id').ilike('username', username)
            if item_id_val: q = q.neq('id', item_id_val)
            if q.execute().data: return jsonify({"success": False, "message": f"Username '{username}' is already taken!"})
            if supabase.table('sys_customers').select('id').ilike('username', username).execute().data:
                return jsonify({"success": False, "message": f"Username '{username}' is already taken!"})
            
        if user_type and mobile:
            q = supabase.table('sys_users').select('id').eq('type', user_type).eq('mobile', mobile)
            if item_id_val: q = q.neq('id', item_id_val)
            if q.execute().data: return jsonify({"success": False, "message": f"Mobile already registered as {user_type}!"})

        if user_type and email:
            q = supabase.table('sys_users').select('id').eq('type', user_type).ilike('email', email)
            if item_id_val: q = q.neq('id', item_id_val)
            if q.execute().data: return jsonify({"success": False, "message": f"Email already registered as {user_type}!"})

    elif table_name == 'customers':
        username = (data.get('username') or '').strip()
        
        if username:
            q = supabase.table('sys_customers').select('id').ilike('username', username)
            if item_id_val: q = q.neq('id', item_id_val)
            if q.execute().data: return jsonify({"success": False, "message": f"Username '{username}' is already taken!"})
            if supabase.table('sys_users').select('id').ilike('username', username).execute().data:
                return jsonify({"success": False, "message": f"Username '{username}' is already taken!"})

        if mobile:
            q = supabase.table('sys_customers').select('id').eq('mobile', mobile)
            if item_id_val: q = q.neq('id', item_id_val)
            if q.execute().data: return jsonify({"success": False, "message": "This mobile number is already registered as a Customer!"})
    # ------------------------------------------
    
    # UPDATE EXISTING RECORD
    if data.get('id'):
        item_id = data.pop('id') # Remove id from payload for update
        
        if table_name == 'users':
            if 'pass' in data:
                if data['pass']:
                    data['pass'] = generate_password_hash(data['pass'])
                else:
                    data.pop('pass')
        elif table_name == 'customers':
            if 'cpass' in data:
                if data['cpass']:
                    data['cpass'] = generate_password_hash(data['cpass'])
                else:
                    data.pop('cpass')

        # Accept Payment Request to Transaction logic
        if table_name == 'requests' and data.get('status') in ['Accepted', 'Approved']:
            req_res = supabase.table('sys_requests').select('*').eq('id', item_id).execute()
            if req_res.data:
                req_data = req_res.data[0]
                if req_data.get('status') not in ['Accepted', 'Approved']:
                    try:
                        nums = re.findall(r'\d+\.?\d*', str(req_data.get('req_qty', '0')))
                        payment_amount = float(nums[0]) if nums else 0.0
                        
                        existing_pay = supabase.table('sys_trans').select('id', 'total').eq('cust', req_data['cust_name']).eq('date', req_data['req_date']).eq('company', req_data['company']).eq('item', 'Payment').execute()
                        if existing_pay.data:
                            old_total = float(existing_pay.data[0].get('total') or 0)
                            new_total = old_total + payment_amount
                            supabase.table('sys_trans').update({"rate": new_total, "total": new_total}).eq('id', existing_pay.data[0]['id']).execute()
                        else:
                            supabase.table('sys_trans').insert({
                                "date": req_data['req_date'], "cust": req_data['cust_name'], "item": 'Payment',
                                "qty": '-', "rate": payment_amount, "total": payment_amount,
                                "company": req_data['company'], "shift": 'Morning'
                            }).execute()
                    except Exception: pass
        
        try:
            res = supabase.table(db_table).update(data).eq('id', item_id).execute()
            return jsonify(res.data[0] if res.data else data)
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})
        
    # 🛡️ BUG FIX: Add server-side check to prevent duplicate transaction entries
    if not data.get('id') and table_name == 'transactions':
        shift_val = data.get('shift')
        
        # DO NOT deduplicate General Bills automatically. They are discrete independent invoices.
        if shift_val != 'General Bill':
            q = supabase.table(db_table).select('id').eq('cust', data.get('cust')).eq('date', data.get('date')).eq('company', data.get('company'))
            
            if shift_val:
                safe_shift = str(shift_val).replace('"', '')
                q = q.or_(f'shift.eq."{safe_shift}",shift.is.null')
                
            if data.get('item') == 'Payment':
                q = q.eq('item', 'Payment')
            else:
                q = q.neq('item', 'Payment')
                
            existing_res = q.execute()
            
            if existing_res.data:
                item_id = existing_res.data[0]['id']
                res = supabase.table(db_table).update(data).eq('id', item_id).execute()
                return jsonify(res.data[0] if res.data else data)

    # INSERT NEW RECORD
    raw_pass = None
    if table_name == 'users':
        if data.get('type') == 'Milk Man':
            owner_res = supabase.table('sys_users').select('login_id').eq('type', 'Owner').eq('company', data.get('company')).execute()
            owner_id = owner_res.data[0]['login_id'] if owner_res.data else "XX"
            
            res = supabase.table('sys_users').select('login_id').eq('type', 'Milk Man').ilike('login_id', f'{owner_id}%').order('id', desc=True).limit(1).execute()
            next_index = 0
            if res.data and res.data[0].get('login_id'):
                last_id = res.data[0]['login_id']
                seq_str = last_id[len(owner_id):]
                try:
                    next_index = int(seq_str, 36) + 1
                except ValueError:
                    pass
            data['login_id'] = f"{owner_id}{get_alphanumeric_sequence(next_index, 2)}"
            
        if data.get('pass'): 
            raw_pass = data['pass']
            data['pass'] = generate_password_hash(data['pass'])
        else: data['pass'] = None

    elif table_name == 'customers':
        milkman_id = data.get('milkman_id')
        if not milkman_id:
            return jsonify({"success": False, "message": "Milkman ID is required"}), 400
        
        res = supabase.table('sys_customers').select('cid').eq('milkman_id', milkman_id).order('id', desc=True).limit(1).execute()
        next_index = 0
        if res.data and res.data[0].get('cid'):
            last_id = res.data[0]['cid']
            seq_str = last_id[len(milkman_id):]
            try:
                next_index = int(seq_str, 36) + 1
            except ValueError:
                pass
        data['cid'] = f"{milkman_id}{get_alphanumeric_sequence(next_index, 2)}"
        if data.get('cpass'): 
            raw_pass = data['cpass']
            data['cpass'] = generate_password_hash(data['cpass'])
        else: data['cpass'] = None

    try:
        res = supabase.table(db_table).insert(data).execute()
        saved_data = res.data[0] if res.data else data
        
        # --- SEND SMS NOTIFICATION (ID, PASS & APP LINK) ---
        if table_name in ['users', 'customers']:
            mobile = saved_data.get('mobile', '')
            login_id = saved_data.get('login_id') or saved_data.get('cid')
            role_name = saved_data.get('type', 'Customer')
            
            if mobile and len(str(mobile)) == 10:
                app_link = "https://my-vender-app.com" # Apni website/app ka link yahan daalein
                sms_message = f"Welcome! Your {role_name} ID: {login_id}, Pass: {raw_pass or 'Not Set'}. Login App: {app_link}"
                
                # NOTE: Asli SMS bhejne ke liye (Fast2SMS/Twilio) yahan unka API integration likhein.
                print(f"🔔 MOCK SMS SENT TO {mobile}: {sms_message}")
                saved_data['sms_status'] = 'sent'
            else:
                saved_data['sms_status'] = 'no_number'
        # ---------------------------------------------------
        
        return jsonify(saved_data)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/api/reset_password', methods=['POST'])
@token_required
def reset_password():
    data = request.json
    requester_id = data.get('requester_id')
    target_id = data.get('target_id')
    target_type = data.get('target_type')
    new_password = data.get('new_password')

    if not new_password:
        return jsonify({"success": False, "message": "New password is required!"}), 400

    if not requester_id or not target_id or not target_type:
        return jsonify({"success": False, "message": "Invalid request. Missing parameters."}), 400

    # SECURITY FIX: Don't trust requester_type from client. Fetch role from DB.
    requester_res = supabase.table('sys_users').select('type').eq('login_id', requester_id).execute()
    if not requester_res.data:
        return jsonify({"success": False, "message": "Requester not found."}), 403
    
    requester_role = requester_res.data[0]['type']

    if requester_role == 'Admin' or (requester_role == 'Owner' and target_type in ['Milk Man', 'Customer', 'Manager']):
        hashed_pass = generate_password_hash(new_password)
        table_to_update = 'sys_customers' if target_type == 'Customer' else 'sys_users'
        id_field = 'cid' if target_type == 'Customer' else 'login_id'
        pass_field = 'cpass' if target_type == 'Customer' else 'pass'
        try:
            supabase.table(table_to_update).update({pass_field: hashed_pass}).eq(id_field, target_id).execute()
            return jsonify({"success": True, "message": "Password reset successfully."})
        except Exception as e:
            return jsonify({"success": False, "message": f"Database Error: {str(e)}"})
        
    return jsonify({"success": False, "message": "Access Denied. You do not have permission to perform this action."}), 403

@app.route('/api/delete_account', methods=['POST'])
@token_required
def delete_account():
    data = request.json
    login_id = data.get('login_id')
    password = data.get('pass')
    admin_override = data.get('admin_override', False)
    admin_pass = data.get('admin_pass')
    
    if not login_id:
        return jsonify({"success": False, "message": "Please provide Login ID!"})
        
    try:
        user_res = supabase.table('sys_users').select('id, pass, type, company').eq('login_id', login_id).execute()
        if not user_res.data:
            return jsonify({"success": False, "message": "Account not found!"})
            
        user = user_res.data[0]
        if user.get('type') != 'Owner':
            return jsonify({"success": False, "message": "Only Owner can delete the company account!"})
            
        if not admin_override:
            if not password:
                return jsonify({"success": False, "message": "Please provide Password!"})
            pass_db = user.get('pass', '')
            is_valid = False
            if pass_db:
                try: is_valid = check_password_hash(pass_db, password)
                except Exception: pass
                
            if not is_valid:
                return jsonify({"success": False, "message": "Incorrect Password! Account deletion failed."})
        else:
            # CRITICAL SECURITY FIX: Verify Admin Password dynamically
            if not admin_pass:
                return jsonify({"success": False, "message": "Admin password required for override!"}), 403
            admin_res = supabase.table('sys_users').select('pass').eq('login_id', 'ADMIN').execute()
            if not admin_res.data or not check_password_hash(admin_res.data[0]['pass'], admin_pass):
                return jsonify({"success": False, "message": "Admin authentication failed!"}), 403
            
        company = user.get('company')
        if company == 'SuperAdmin':
            return jsonify({"success": False, "message": "SuperAdmin account cannot be deleted!"})
            
        # Delete associated data for this company
        supabase.table('sys_trans').delete().eq('company', company).execute()
        supabase.table('sys_requests').delete().eq('company', company).execute()
        supabase.table('sys_routes').delete().eq('company', company).execute()
        supabase.table('sys_products').delete().eq('company', company).execute()
        supabase.table('sys_customers').delete().eq('company', company).execute()
        supabase.table('sys_users').delete().eq('company', company).execute()
        supabase.table('sys_licenses').delete().eq('used_by', login_id).execute()
        
        return jsonify({"success": True, "message": "Account and all associated company data deleted successfully!"})
    except Exception as e:
        print("Delete Account Error:", e)
        return jsonify({"success": False, "message": f"An error occurred: {str(e)}"})

@app.route('/api/<table_name>/<item_id>', methods=['DELETE'])
@token_required
def delete_data(table_name, item_id):
    if table_name not in ['users', 'customers', 'transactions', 'products', 'requests', 'routes', 'licenses']:
        return jsonify({"success": False, "message": "Invalid table"}), 400
    db_table = 'sys_' + (table_name if table_name != 'transactions' else 'trans')
    supabase.table(db_table).delete().eq('id', item_id).execute()
    return jsonify({"success": True})

@app.route('/api/verify_key', methods=['POST'])
def verify_key():
    data = request.json
    key = (data.get('key') or '').strip().upper()
    owner_id = data.get('owner_id')
    
    if not key:
        return jsonify({'success': False, 'message': 'Invalid Key'})
        
    res = supabase.table('sys_licenses').select('*').eq('key_code', key).eq('status', 'Active').execute()
    if res.data:
        license_data = res.data[0]
        duration_days = 30  # Default duration
        try:
            # Safely get duration from DB, handle None or invalid values
            db_duration = license_data.get('duration_days')
            if db_duration is not None:
                duration_days = int(db_duration)
        except (ValueError, TypeError):
            pass  # If conversion fails, use the default 30 days

        owner_res = supabase.table('sys_users').select('license_expiry').eq('login_id', owner_id).execute()
        if not owner_res.data:
            return jsonify({'success': False, 'message': 'Owner not found.'})

        owner_data = owner_res.data[0]
        current_expiry_str = owner_data.get('license_expiry')

        # Use timezone-aware datetime objects (UTC)
        base_date = datetime.datetime.now(datetime.timezone.utc)
        if current_expiry_str:
            try:
                current_expiry_date = datetime.datetime.fromisoformat(current_expiry_str.replace('Z', '+00:00'))
                # If the stored date is naive, assume it's UTC
                if current_expiry_date.tzinfo is None:
                    current_expiry_date = current_expiry_date.replace(tzinfo=datetime.timezone.utc)

                if current_expiry_date > base_date:
                    base_date = current_expiry_date
            except (ValueError, TypeError):
                # If parsing fails, just use current date as base.
                pass

        new_expiry_date = base_date + datetime.timedelta(days=duration_days)
        try:
            supabase.table('sys_licenses').update({'status': 'Used', 'used_by': owner_id, 'used_on': datetime.datetime.now(datetime.timezone.utc).isoformat()}).eq('id', license_data['id']).execute()
            supabase.table('sys_users').update({'license_expiry': new_expiry_date.isoformat()}).eq('login_id', owner_id).execute()
            return jsonify({'success': True, 'message': f'License extended! New expiry: {new_expiry_date.strftime("%d-%b-%Y")}', 'new_expiry': new_expiry_date.isoformat()})
        except Exception as e:
            return jsonify({'success': False, 'message': f'Database Error: {str(e)}'})

    return jsonify({'success': False, 'message': 'Invalid or Expired Key'})

# New API to get opening balance for a customer for a specific month/year
@app.route('/api/opening_balance', methods=['GET'])
@token_required
def get_opening_balance():
    cust_name = request.args.get('cust_name')
    company = request.args.get('company')
    
    try:
        month = int(request.args.get('month', 0))
        year = int(request.args.get('year', 0))
    except (TypeError, ValueError):
        return jsonify({"opening_balance": 0, "transactions": [], "error": "Invalid month or year parameters"}), 400

    # Bill ke liye customer ka address aur mobile fetch karein
    customer_details = {}
    if cust_name and company:
        try:
            customer_res = supabase.table('sys_customers').select('addr, mobile').eq('name', cust_name).eq('company', company).limit(1).execute()
            if customer_res.data:
                customer_details = customer_res.data[0]
        except Exception as e:
            print(f"Error fetching customer details for bill: {e}")

    # Fetch all transactions (removed .neq('shift') because it incorrectly excludes old NULL shift records)
    transactions_res = supabase.table('sys_trans').select('*').eq('cust', cust_name).eq('company', company).execute()
    transactions_all = transactions_res.data if transactions_res.data else []

    opening_balance = 0
    month_transactions = []

    for t in transactions_all:
        if t.get('shift') == 'General Bill':
            continue
        d_str = str(t.get('date', '')).strip()
        t_year, t_month = 0, 0
        try:
            # Standardize date parsing
            parts = re.split(r'[-/]', d_str)
            if len(parts) == 3:
                if len(parts[0]) == 4: # YYYY-MM-DD
                    t_year, t_month = int(parts[0]), int(parts[1])
                elif len(parts[2]) == 4: # DD-MM-YYYY
                    t_year, t_month = int(parts[2]), int(parts[1])
                elif len(parts[2]) == 2: # DD-MM-YY
                    t_year, t_month = 2000 + int(parts[2]), int(parts[1])
        except (ValueError, IndexError):
            continue
            
        if t_year > 0 and t_month > 0:
            if t_year < year or (t_year == year and t_month < month):
                try:
                    total_val = float(t.get('total') or 0)
                except (ValueError, TypeError):
                    total_val = 0.0

                if t['item'] == 'Payment':
                    opening_balance -= abs(total_val)
                else:
                    opening_balance += total_val
            elif t_year == year and t_month == month:
                month_transactions.append(t)
    
    return jsonify({
        "opening_balance": opening_balance, 
        "transactions": month_transactions,
        "customer_details": customer_details
    })

# --- SERVER-SIDE PAGINATION EXAMPLE API ---
@app.route('/api/transactions/page', methods=['GET'])
@token_required
def get_transactions_paginated():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 25))
    company = request.args.get('company')
    
    offset = (page - 1) * per_page
    
    try:
        res = supabase.table('sys_trans').select('*', count='exact').eq('company', company).order('id', desc=True).range(offset, offset + per_page - 1).execute()
        return jsonify({
            "success": True,
            "data": res.data,
            "total_count": res.count,
            "page": page,
            "per_page": per_page
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

# Android App se communication ke liye functions
@app.route('/api/print_command', methods=['POST'])
def print_command():
    # Yeh endpoint Android app se print command receive karne ke liye hai.
    # Asli printing client-side (Android app me) hi handle honi chahiye.
    # Iska istemal server par log karne ke liye kiya ja sakta hai ki print action kab hua.
    data = request.json or {}
    print(f"ANDROID PRINT COMMAND RECEIVED: {data.get('info', 'No info')}")
    return jsonify({"success": True, "message": "Print command received by server."})

@app.route('/api/back_command', methods=['POST'])
def back_command():
    # Yeh endpoint Android app se back command receive karne ke liye hai.
    # 'Back' action client-side (Android app) navigation ka hissa hai.
    # Iska istemal user navigation ko track karne ke liye kiya ja sakta hai.
    data = request.json or {}
    print(f"ANDROID BACK COMMAND RECEIVED: From page {data.get('page', 'Unknown')}")
    return jsonify({"success": True, "message": "Back command received by server."})

# Vercel par app start hote hi admin user check karne aur banane ke liye isse yahan call karein
ensure_admin()

if __name__ == '__main__':
    print("Backend Chal Raha Hai... Browser Me Login Karein!")
    app.run(host='0.0.0.0', debug=True, port=5000)
