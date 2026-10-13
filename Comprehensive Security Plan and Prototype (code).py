import os
import base64
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


all_users = {}
active_sessions = {}
env_key_b64 = os.environ.get("AES_KEY_B64")
if env_key_b64:
 secret_key_from_env = base64.b64decode(env_key_b64)
else:
 secret_key_from_env = AESGCM.generate_key(bit_length=256)

data_locker = AESGCM(secret_key_from_env)



def make_password_hash(user_password, user_salt):
 kdf = PBKDF2HMAC(
  algorithm=hashes.SHA256(),
  length=32,
  salt=user_salt,
  iterations=100000
 )
 return kdf.derive(user_password.encode())

def check_password(user_password, salt_as_b64, stored_hash_as_b64):
 decoded_salt = base64.b64decode(salt_as_b64)
 stored_hash = base64.b64decode(stored_hash_as_b64)
 kdf = PBKDF2HMAC(
  algorithm=hashes.SHA256(),
  length=32,
  salt=decoded_salt,
  iterations=100000
 )
 test_hash = kdf.derive(user_password.encode())
 if test_hash == stored_hash:
  return True
 else:
  return False

def scramble_address(address_text):
 random_nonce_bytes = secrets.token_bytes(12)
 scrambled_version = data_locker.encrypt(random_nonce_bytes, address_text.encode(), None)
 return base64.b64encode(random_nonce_bytes).decode(), base64.b64encode(scrambled_version).decode()



def unscramble_address(nonce_as_b64, scrambled_as_b64):
 return data_locker.decrypt(
  base64.b64decode(nonce_as_b64),
  base64.b64decode(scrambled_as_b64),
  None
 ).decode()

def make_new_user(username, password, address, role="customer"):
 random_salt = secrets.token_bytes(16)
 user_pw_hash = make_password_hash(password, random_salt)
 nonce_as_b64, scrambled_as_b64 = scramble_address(address)
 all_users[username] = {
  "password_hash": base64.b64encode(user_pw_hash).decode(),
  "salt": base64.b64encode(random_salt).decode(),
  "role": role,
  "address_nonce": nonce_as_b64,
  "address_ciphertext": scrambled_as_b64
 }




def login(username, password):
 user_record = all_users.get(username)
 if not user_record:
  return None
 if not check_password(password, user_record["salt"], user_record["password_hash"]):
  return None
 new_token = secrets.token_hex(8)
 active_sessions[new_token] = username
 return new_token

def see_my_own_data(session_token):
 user_name_from_token = active_sessions.get(session_token)
 if not user_name_from_token:
  return None
 user_record = all_users[user_name_from_token]
 clear_address = unscramble_address(user_record["address_nonce"], user_record["address_ciphertext"])
 return {"username": user_name_from_token, "role": user_record["role"], "address": clear_address}


def admin_add_user(admin_token, username, password, address, role="customer"):
 caller = active_sessions.get(admin_token)
 if not caller:
  return False
 if all_users[caller]["role"] != "admin":
  return False
 make_new_user(username, password, address, role)
 return True





def admin_show_all_users(admin_token):
 caller = active_sessions.get(admin_token)
 if not caller:
  return None
 if all_users[caller]["role"] != "admin":
  return None
 return [
  {"username": uname, "role": record["role"], "address_ciphertext": record["address_ciphertext"]}
  for uname, record in all_users.items()
 ]



def main():
 print("\nstep 1: made a key. it's", len(secret_key_from_env), "bytes big.")

 make_new_user("admin_guy", "admin_password", "0 Admin Road", "admin")
 admin_token = login("admin_guy", "admin_password")
 print("\n\nstep 2 -> admin logged in and got a token")
 print("token is:", admin_token, "\n")



 admin_add_user(admin_token, "alice", "alice_password", "42 Banana Peel Street", "customer")
 admin_add_user(admin_token, "bob", "bob_password", "99 Chicken Nugget Lane", "customer")
 admin_add_user(admin_token, "charlie", "charlie_password", "777 Funky Donkey Drive", "customer")
 admin_add_user(admin_token, "dana", "dana_password", "1234 Potato Chip Court", "customer")

 customer_token = login("alice", "alice_password")
 if customer_token:
  print("\nstep 3: alice logged in and sees her info:")
  print(see_my_own_data(customer_token), "\n")


 print("step 4: admin looks at everyone (addresses stay scrambled)")
 all_records = admin_show_all_users(admin_token)
 if all_records:
  for record in all_records:
   print("  ", record)
 print()


 print("step 5: customer tries admin thing")
 bad_try = admin_show_all_users(customer_token)
 if not bad_try:
  print("blocked: customer not allowed here")

if __name__ == "__main__":
 main()
