import hashlib

def hash_message(message):
    return int(hashlib.sha256(message.encode()).hexdigest(), 16)

def sign_message(message, sk, p, g):
    # k = k_used_in_step_1
    h = hash_message(message)
    r = pow(g, p) % p
    s = (sk * h ) % (p - 1)
    return (r, s)

def verify_message(message, signature, p, g, pk):
    r, s = signature
    h = hash_message(message)
    y = pow(g, h, p)
    x = pow(y, r, p) * pow(pk, s, p)
    return x == r

def sign_as_alice(message, sk, p, g, pk):
    signature = sign_message(message, sk, p, g)
    if verify_message(message, signature, p, g, pk):
        return signature
    else:
        print("Could not sign message as Alice.")

# Input parameters from Step 1
p = 23
g = 5
pk = 25874695745699
sk = 857777

# List of messages to sign
messages = [
    "data confidentiality",
    "data integrity",
    "authentication",
    "non-repudiation"
]

# Sign messages as Alice
impersonated = {}
for message in messages:
    signature = sign_as_alice(message, sk, p, g, pk)
    if signature:
        impersonated[message] = signature

# Output impersonated hash
print("Impersonated:")
for message, signature in impersonated.items():
    print(f"{message}: {signature}")
# Output key hash
key_hash = {
    "p": p,
    "g": g,
    "pk": pk,
    "sk": sk
}
print("Key Hash:")
print(key_hash)
