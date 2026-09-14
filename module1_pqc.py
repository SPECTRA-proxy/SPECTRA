import oqs
import time

print("=== SPECTRA - Module 1: Adaptive PQC Transport ===")
print("Algorithm: ML-KEM-768")
print()

with oqs.KeyEncapsulation("ML-KEM-768") as kem:

    # Key generation
    start = time.perf_counter_ns()
    public_key = kem.generate_keypair()
    keygen_time = (time.perf_counter_ns() - start) / 1000

    # Encapsulation
    start = time.perf_counter_ns()
    ciphertext, server_secret = kem.encap_secret(public_key)
    encap_time = (time.perf_counter_ns() - start) / 1000

    # Decapsulation
    start = time.perf_counter_ns()
    client_secret = kem.decap_secret(ciphertext)
    decap_time = (time.perf_counter_ns() - start) / 1000

    # Verification
    match = server_secret == client_secret

print("Key generation:      %.2f microseconds" % keygen_time)
print("Encapsulation:       %.2f microseconds" % encap_time)
print("Decapsulation:       %.2f microseconds" % decap_time)
print("Shared secret match: ", "PASS" if match else "FAIL")
print()

if match:
    print("ML-KEM-768 key exchange: SUCCESS")
else:
    print("ML-KEM-768 key exchange: FAILED")