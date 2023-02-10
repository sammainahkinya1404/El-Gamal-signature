import json

def verify_signature(key, r, s, text):
    p = int(key["p"])
    g = int(key["g"])
    pk = int(key["pk"])

    return (pow(g, int(hash(text)), p) * pow(pk, r, p)) % p == pow(r, s, p)

with open("sample _data _new.json") as f:
    data = json.load(f)
    srn = data["srn"]
    name = data["name"]
    key = data["exercise"]["key"]

    for intercepted in data["exercise"]["intercepted"]:
        text = intercepted["text"]
        signature = intercepted["signature"]
        r = int(signature["r"])
        s = int(signature["s"])

        if verify_signature(key, r, s, text):
            print(f"{text} is authentic")
        else:
            print(f"{text} is NOT authentic")
# Verify the signature for each intercepted message
output = []
for intercepted in data["exercise"]["intercepted"]:
    text = intercepted["text"]
    signature = intercepted["signature"]
    r = int(signature["r"])
    s = int(signature["s"])
    
    if verify_signature(key, r, s, text):
        output.append(text)

# Save the output to a solution.json file
with open("solution.json", "w") as f:
    json.dump({"srn": data["srn"], "name": data["name"], "solution": output}, f)

