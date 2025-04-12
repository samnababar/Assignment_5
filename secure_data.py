# 🔒 Secure Data Encryption System
import streamlit as st
import hashlib
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

# ======================
# PAGE CONFIG (MUST BE FIRST)
# ======================
st.set_page_config(
    page_title="Secure Vault",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="expanded"
)

# ======================
# CONSTANTS
# ======================
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes in seconds

# ======================
# ENCRYPTION SETUP
# ======================
@st.cache_resource
def get_cipher():
    KEY = Fernet.generate_key()
    return Fernet(KEY)

cipher = get_cipher()

# ======================
# SESSION STATE
# ======================
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'lockout_until' not in st.session_state:
    st.session_state.lockout_until = None

# ======================
# SECURITY FUNCTIONS
# ======================
def hash_passkey(passkey, salt=None):
    """Secure hashing with optional salt"""
    if not salt:
        salt = datetime.now().strftime("%Y%m%d%H%M%S")
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000).hex()

def encrypt_data(text):
    """Encrypt data using Fernet"""
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    """Decrypt data using Fernet"""
    return cipher.decrypt(encrypted_text.encode()).decode()

def check_lockout():
    """Check if system is in lockout state"""
    if st.session_state.lockout_until and datetime.now() < st.session_state.lockout_until:
        remaining = (st.session_state.lockout_until - datetime.now()).seconds // 60
        st.error(f"🔒 System locked. Try again in {remaining + 1} minutes.")
        return True
    return False

# ======================
# STREAMLIT UI
# ======================
def main():
    st.sidebar.title("🔐 Navigation")
    menu = ["Home", "Store Data", "Retrieve Data", "Login"]
    choice = st.sidebar.radio("Go to", menu)

    if choice == "Home":
        show_home()
    elif choice == "Store Data":
        show_store_data()
    elif choice == "Retrieve Data":
        show_retrieve_data()
    elif choice == "Login":
        show_login()

def show_home():
    """Home page with introduction"""
    st.title("🔒 Secure Data Vault")
    st.markdown("""
    ## Welcome to Your Secure Data System
    
    This application allows you to:
    - 🔐 **Store sensitive data** with military-grade encryption
    - 🔑 **Retrieve data** only with the correct passkey
    - 🛡️ **Automatic lockout** after multiple failed attempts
    """)
    
    if st.session_state.stored_data:
        st.info(f"ℹ️ System currently stores {len(st.session_state.stored_data)} encrypted records")

def show_store_data():
    """Page for storing new encrypted data"""
    st.title("📥 Store New Data")
    
    with st.form("store_form"):
        user_data = st.text_area("Enter sensitive data:", height=150)
        passkey = st.text_input("Create strong passkey:", type="password")
        reference = st.text_input("Reference name (optional):")
        
        if st.form_submit_button("🔒 Encrypt & Store"):
            if user_data and passkey:
                ref_id = reference or f"entry_{len(st.session_state.stored_data) + 1}"
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data)
                
                st.session_state.stored_data[ref_id] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                
                st.success("✅ Data stored securely!")
                st.code(f"Reference ID: {ref_id}\nEncrypted: {encrypted_text[:50]}...")
            else:
                st.error("⚠️ Both data and passkey are required!")

def show_retrieve_data():
    """Page for retrieving encrypted data"""
    st.title("📤 Retrieve Your Data")
    
    if check_lockout():
        return
        
    if not st.session_state.stored_data:
        st.warning("No data stored yet. Store some data first!")
        return
    
    with st.form("retrieve_form"):
        ref_id = st.selectbox("Select data to retrieve:", 
                            options=list(st.session_state.stored_data.keys()))
        passkey = st.text_input("Enter passkey:", type="password")
        
        if st.form_submit_button("🔓 Decrypt Data"):
            entry = st.session_state.stored_data[ref_id]
            
            if hash_passkey(passkey) == entry["passkey"]:
                st.session_state.failed_attempts = 0
                decrypted = decrypt_data(entry["encrypted_text"])
                st.success("✅ Decryption successful!")
                st.text_area("Decrypted Data:", value=decrypted, height=200)
                st.caption(f"Stored on: {entry['timestamp']}")
            else:
                st.session_state.failed_attempts += 1
                remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
                
                if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                    st.session_state.lockout_until = datetime.now() + timedelta(seconds=LOCKOUT_TIME)
                    st.error("🚨 Too many failed attempts! System locked for 5 minutes.")
                else:
                    st.error(f"❌ Incorrect passkey! {remaining} attempts remaining")

def show_login():
    """Login page for lockout situations"""
    st.title("🔑 Administrator Login")
    
    if st.session_state.lockout_until:
        if datetime.now() < st.session_state.lockout_until:
            remaining = (st.session_state.lockout_until - datetime.now()).seconds // 60
            st.error(f"System locked. {remaining + 1} minutes remaining.")
        else:
            st.session_state.lockout_until = None
            st.session_state.failed_attempts = 0
            st.success("Lockout period expired. You may try again.")
    
    with st.form("login_form"):
        password = st.text_input("Enter administrator password:", type="password")
        
        if st.form_submit_button("Login"):
            if password == "SecureVault123!":
                st.session_state.failed_attempts = 0
                st.session_state.lockout_until = None
                st.success("✅ Login successful! Redirecting...")
                st.experimental_rerun()
            else:
                st.error("❌ Incorrect password")

if __name__ == "__main__":
    main()