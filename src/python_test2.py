import hmac
import hashlib

# From your C debug output
parent_priv_hex = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
parent_chain_code_hex = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
hmac_input_data_hex = "00e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b3580000000"  # From your debug

# Convert to bytes
parent_priv = bytes.fromhex(parent_priv_hex)
parent_chain_code = bytes.fromhex(parent_chain_code_hex)
hmac_input_data = bytes.fromhex(hmac_input_data_hex)

# Step 1: Compute HMAC-SHA512
digest = hmac.new(parent_chain_code, hmac_input_data, hashlib.sha512).digest()
digest_hex = digest.hex()
print("Computed HMAC output:", digest_hex)

# Step 2: Extract IL (left 32 bytes) and child chain code (right 32 bytes)
il = digest[:32]
child_chain_code = digest[32:]
print("Computed IL (left 32 bytes):", il.hex())
print("Computed child chain code (right 32 bytes):", child_chain_code.hex())

# Step 3: Compute child private key = (parent_priv + IL) mod n
n = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
parent_priv_int = int.from_bytes(parent_priv, 'big')
il_int = int.from_bytes(il, 'big')
child_priv_int = (parent_priv_int + il_int) % n
child_priv_bytes = child_priv_int.to_bytes(32, 'big')  # Ensure 32 bytes with leading zeros
print("Computed child private key:", child_priv_bytes.hex())

# Step 4: Compare with expected values from BIP-32 Test Vector 1, m/0'
expected_child_chain = "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
expected_child_priv = "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"

print("\nVerification:")
print("Child chain match:", child_chain_code.hex() == expected_child_chain)
print("Child priv match:", child_priv_bytes.hex() == expected_child_priv)
