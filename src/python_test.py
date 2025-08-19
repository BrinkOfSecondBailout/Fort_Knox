import hmac
import hashlib

#key = bytes.fromhex("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
#data = bytes.fromhex("00e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b3580000000")
#digest = hmac.new(key, data, hashlib.sha512).hexdigest()
#print(digest)


# BIP-32 Test Vector 1 data
parent_priv = 0xe8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
parent_chain_code = 0x873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
index = 0x80000000  # Hardened index 0'
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1 order

# Step 1: Compute HMAC-SHA512
key = parent_chain_code.to_bytes(32, 'big')
data = b'\x00' + parent_priv.to_bytes(32, 'big') + index.to_bytes(4, 'big')
print("HMAC input data:", data.hex())
print("HMAC key (parent chain code):", key.hex())

digest = hmac.new(key, data, hashlib.sha512).digest()
print("HMAC output:", digest.hex())

# Step 2: Extract IL (left 32 bytes) and child chain code (right 32 bytes)
il = digest[:32]
child_chain_code = digest[32:]
print("IL (left 32 bytes)          :", il.hex())
print("Child chain (right 32 bytes):", child_chain_code.hex())

# Step 3: Compute child private key: child_priv = (parent_priv + IL) mod n
il_int = int.from_bytes(il, 'big')
child_priv = (parent_priv + il_int) % n
child_priv_bytes = child_priv.to_bytes(32, 'big')  # Ensure 32 bytes

# Step 4: Validate against expected values (Test Vector 1, m/0')
expected_child_priv = "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
expected_child_chain = "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
print("Expected child priv:  ", expected_child_priv)
print("Got child priv:       ", child_priv_bytes.hex())
print("Expected child chain: ", expected_child_chain)
print("Got child chain:      ", child_chain_code.hex())
print("Child priv match:     ", child_priv_bytes.hex() == expected_child_priv)
print("Child chain match:    ", child_chain_code.hex() == expected_child_chain)
