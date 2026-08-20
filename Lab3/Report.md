Lab 3: Data Protection — Encryption & Key Management

Course: IKB42603 Cloud Computing Security Essentials 
Lab: Lab 3 Topic: At-rest & in-transit encryption, envelope encryption, cryptographic erasure — OpenSSL & LocalStack KMS Environment: OpenSSL (Git Bash), nginx container for TLS, LocalStack KMS on localhost:4566 
Name: frhntasha

Lab Summary // Objective

This report covers seven hands-on tasks in data protection:

Encrypting data at rest with symmetric (AES) and asymmetric (RSA) cryptography, and verifying digital signatures.
Protecting data in transit with TLS using a self-signed certificate.
Using LocalStack's Key Management Service (KMS) to implement envelope encryption.
Applying per-tenant keys and cryptographic erasure to make data provably unrecoverable.
Verifying data integrity with hashing and building a tamper-evident hash chain.

Overview

The lab runs across two sessions:

Session A: Cryptographic fundamentals by hand — symmetric encryption, asymmetric encryption with signatures, and TLS.
Session B: How a cloud KMS manages keys at scale — envelope encryption, per-tenant keys, cryptographic erasure, and integrity verification.
Session A — Encryption Fundamentals
Task 1 — Symmetric Encryption (Data at Rest)
echo 'Patient: Ahmad, Diagnosis: confidential' > record.txt

openssl enc -aes-256-cbc -pbkdf2 -salt -in record.txt -out record.enc

cat record.enc

openssl enc -d -aes-256-cbc -pbkdf2 -in record.enc -out record.dec.txt

diff record.txt record.dec.txt && echo 'MATCH: decryption successful'

Explanation: A sample sensitive file is encrypted with AES-256 in CBC mode, using a passphrase as the single shared key. cat record.enc confirms the ciphertext is unreadable, and decrypting with the same passphrase reproduces the original file exactly — confirmed by diff finding no difference.

Output:

MATCH: decryption successful

Evidence:
<img width="1375" height="540" alt="01-aes-match" src="https://github.com/user-attachments/assets/0395843b-4a7d-42c9-a175-ff58effeb3ef" />

Report answer — key-distribution problem with symmetric encryption: Symmetric encryption uses one shared key for both encryption and decryption, so that key has to somehow reach every party who needs to decrypt the data — and whoever intercepts it during that exchange can read everything encrypted with it. In the cloud, where data and services are distributed across networks and accounts, safely getting that one key to every legitimate party without it leaking in transit or at rest becomes the hard part, not the encryption itself.

Task 2 — Asymmetric Encryption & Digital Signatures
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

openssl pkeyutl -encrypt -pubin -inkey public.pem -in record.txt -out record.rsa
openssl pkeyutl -decrypt -inkey private.pem -in record.rsa -out record.rsa.txt

openssl dgst -sha256 -sign private.pem -out record.sig record.txt
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt

Explanation: A 2048-bit RSA key pair is generated. Encryption uses the public key so anyone can encrypt a message, but only the private key holder can decrypt it. Signing reverses the roles: the private key signs the file (proving it came from this key holder), and the public key verifies that signature — proving both origin and that the file hasn't been altered.

Output:

Verified OK

Evidence:
<img width="783" height="345" alt="02-rsa-verify" src="https://github.com/user-attachments/assets/e7168ead-ab0f-4d67-973f-5835d7cb1137" />

Task 3 — Encryption in Transit (TLS)
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
 -days 7 -nodes -subj '/CN=localhost' \
 -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'

docker run -d --name tls -p 8443:443 \
 -v $(pwd)/cert.pem:/etc/nginx/cert.pem \
 -v $(pwd)/key.pem:/etc/nginx/key.pem \
 -v $(pwd)/record.txt:/usr/share/nginx/html/record.txt \
 -v $(pwd)/nginx.conf:/etc/nginx/conf.d/default.conf \
 nginx

curl -k -4 https://localhost:8443/record.txt

Explanation: A self-signed certificate is generated for localhost, with a Subject Alternative Name extension included since modern TLS clients expect SAN rather than relying on the CN field alone. An nginx container serves record.txt over HTTPS on port 443 (mapped to host port 8443), using a custom nginx config to enable SSL with the generated cert and key. curl -k connects over TLS (ignoring the self-signed cert warning) and successfully retrieves the file — proof the channel is encrypted end to end.

Output:

Patient: Ahmad, Diagnosis: confidential

Evidence:
<img width="781" height="186" alt="03-tls-curl" src="https://github.com/user-attachments/assets/2c45c97a-24e5-4125-b532-4c485807df86" />

Session B — Key Management, Envelope Encryption & Erasure
Task 4 — Create and Use a KMS Master Key
EP='--endpoint-url=http://localhost:4566'

aws $EP kms create-key --description 'CCSE tenant-A master key'

KEY_A=76e962a3-178b-43d6-950e-8952cfd70d15

aws $EP kms encrypt --key-id $KEY_A --plaintext "$(echo -n 'hello' | base64)" \
 --query CiphertextBlob --output text

Explanation: A customer master key (CMK) is created in LocalStack's KMS emulator. The key's ID is then used directly to encrypt a small plaintext secret, producing a ciphertext blob — this direct approach works for small data, but doesn't scale to larger files (that's what envelope encryption in Task 5 solves).

Output (KeyId):

KeyId: 76e962a3-178b-43d6-950e-8952cfd70d15

Evidence:
<img width="1245" height="615" alt="04-kms-key-encrypt" src="https://github.com/user-attachments/assets/62b943f6-65f7-4fa1-bcf5-dff605dac3b8" />

Task 5 — Envelope Encryption
aws $EP kms generate-data-key --key-id $KEY_A --key-spec AES_256 \
 --query '[Plaintext,CiphertextBlob]' --output text

# saved as datakey.b64 (plaintext) and datakey.enc (wrapped)

base64 -d datakey.b64 > datakey.bin
openssl enc -aes-256-cbc -pbkdf2 -in record.txt -out record.env.enc \
 -pass file:./datakey.bin

rm datakey.bin datakey.b64
echo 'Only the KMS-wrapped data key (datakey.enc) remains.'

Explanation: Rather than encrypting the file directly with the master key, KMS generates a one-time data key, returned in two forms: plaintext (used locally to encrypt the file) and a KMS-wrapped ciphertext (safe to store alongside the encrypted data). The plaintext copy is used once to encrypt record.txt locally with AES, then immediately deleted from disk — only the wrapped datakey.enc remains, which can only be unwrapped again by asking KMS to decrypt it with the master key.

Output:

Only the KMS-wrapped data key (datakey.enc) remains.

Evidence:
<img width="1711" height="417" alt="05-envelope-encryption" src="https://github.com/user-attachments/assets/517b9230-33fc-4ce5-96d8-b76331a47558" />

Report answer — why envelope encryption, and why only the master key needs hardware-grade protection: Encrypting large or frequent data directly with a master key inside a KMS would be slow and doesn't scale. Envelope encryption solves this by generating a disposable data key for each encryption operation — the bulk data is encrypted locally and fast with that data key, while only the small data key itself is wrapped by the master key. Because the master key never leaves the KMS and is only ever used to wrap/unwrap small data keys (not bulk data), it's the one piece that needs the strongest protection — everything downstream depends on it staying secure, but it's a much smaller surface to protect than the data itself.

Task 6 — Per-Tenant Keys & Cryptographic Erasure
aws $EP kms create-key --description 'CCSE tenant-B master key'
KEY_B=8a73fd2d-9bc4-4b14-a547-0dc70420d1a4

aws $EP kms schedule-key-deletion --key-id $KEY_A --pending-window-in-days 7

aws $EP kms disable-key --key-id $KEY_A

aws $EP kms decrypt --ciphertext-blob fileb://datakey.enc

Explanation: A separate master key is created for tenant B, isolated from tenant A's key — each tenant's data can only ever be unwrapped by its own key. Tenant A's key is then scheduled for deletion, simulating cryptographic erasure. Once a key enters PendingDeletion, LocalStack refuses further state changes on it (the disable-key call fails because the key is already pending deletion), and any attempt to use it to decrypt — including unwrapping tenant A's data key — is rejected.

Output:

schedule-key-deletion → KeyState: "PendingDeletion", DeletionDate: 2026-08-28

disable-key → ERROR: KMSInvalidStateException — key is pending deletion

kms decrypt → ERROR: NotFoundException — Invalid keyId

Evidence:
<img width="1767" height="837" alt="06-crypto-erasure" src="https://github.com/user-attachments/assets/aee10570-f8e8-4959-a002-93a270a39180" />

Task 7 — Integrity & Tamper-Evidence
sha256sum record.txt

cp record.txt tampered.txt
echo 'x' >> tampered.txt
sha256sum record.txt tampered.txt

Explanation: record.txt is fingerprinted with SHA-256. A copy is tampered with by appending a single character, and hashing both files side by side shows their hashes differ completely — proving hashing detects even the smallest change to the underlying data.

Output:

9345a32351cc1ad03e8b318059b753da6cd4e325688da97a01599b32bc945dd5 *record.txt
8c8afc8a3e34425ab38ef90213102c638a82f756bd7187a03b306c5683065eb7 *tampered.txt

Evidence:
<img width="810" height="257" alt="07a-hash-tamper" src="https://github.com/user-attachments/assets/77edc5cc-3d5b-4f42-b6af-f0f6db82f504" />

PREV=0
for line in 'login ok' 'file read' 'export data'; do \
 PREV=$(echo -n "$PREV$line" | sha256sum | cut -d' ' -f1); \
 echo "$line | $PREV"; done

Explanation: Each log entry's hash is computed from the entry's text combined with the previous entry's hash, chaining every entry to the one before it. Changing any entry — even far back in the chain — would change its hash and every hash after it, making tampering with the log immediately visible.

Output:

login ok | 573f9af26d45d395a1089ef5fec4d50ccddc17c0ea4269c2c91d90929a820053
file read | 6c3adc61ece69412b338e43d761435e95dbfc948253f8f600087b0a4c5ad2d3d
export data | e1470ccfaf43dcab3c17d5710dc9eacbb7ac65c9f522ca98c2c503431b32da68

Evidence:
<img width="775" height="148" alt="07b-hash-chain" src="https://github.com/user-attachments/assets/75389b0c-2a27-452e-b7a3-24b76c70d4d6" />

Short-Answer Questions

Q1. Compare symmetric and asymmetric encryption: speed, key distribution, and typical use. Symmetric encryption (like AES) is fast and efficient for large volumes of data, but requires safely getting the same shared key to every party who needs to decrypt — a hard distribution problem, especially across networks. Asymmetric encryption (like RSA) sidesteps that by splitting the key into a public half anyone can use to encrypt and a private half only the owner holds — no shared secret ever needs to travel — but it's computationally much slower, so it's typically used for small payloads, key exchange, and signatures rather than bulk data encryption.

Q2. Why is key management described as the weakest link, not the algorithm? Modern encryption algorithms like AES-256 and RSA-2048 are computationally infeasible to break directly with current technology. What actually fails in practice is how the keys around that strong algorithm are handled — a key left in a config file, logged accidentally, never rotated, or shared insecurely defeats the encryption entirely regardless of how strong the algorithm is. The math is solid; it's the human and operational processes around the key's lifecycle that tend to break down.

Q3. Explain envelope encryption and why only the master key needs hardware-grade protection. Envelope encryption uses a disposable data key to encrypt the actual data locally and quickly, then wraps that data key with a master key managed by the KMS. The bulk data never needs to touch the master key directly, and the data key only exists in plaintext briefly during the encryption operation before being discarded. Because everything downstream — every data key, every encrypted file — ultimately depends on the master key staying secure, it's the one component worth the cost of hardware-grade protection (like an HSM); protecting every data key to that same standard wouldn't be practical or necessary.

Q4. How does cryptographic erasure achieve provable deletion where overwriting cannot (in the cloud)? In the cloud, the underlying physical storage is virtualized, replicated, and often outside the customer's direct control, so there's no reliable way to guarantee every copy of a file has been physically overwritten. Cryptographic erasure sidesteps that entirely: if the data was encrypted and the key that protects it is destroyed, the ciphertext left behind is permanently unreadable no matter how many copies exist or where they're stored — deleting one small key is provable and immediate, whereas finding and overwriting every replica of the data is not.

Q5. How does a hash chain make a log tamper-evident? Each entry's hash incorporates the hash of the entry before it, so every entry is cryptographically linked to the entire history that came before it. If an attacker alters any single entry — even one deep in the log's history — that entry's hash changes, which cascades and changes every subsequent hash in the chain. Recomputing the chain and comparing it to the stored hashes immediately reveals exactly where tampering occurred, which is what makes the log tamper-evident rather than just tamper-resistant.

Verification Command
aws --endpoint-url=http://localhost:4566 kms list-keys
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt

Cleanup & Teardown
docker stop tls 2>/dev/null
rm -f record.* private.pem public.pem key.pem cert.pem datakey.* tampered.txt
docker stop localstack && docker rm localstack

Security Best-Practices Checklist
- Data encrypted at rest (AES) and decryption verified.
- Asymmetric keys used correctly (encrypt with public, sign with private).
- Data protected in transit with TLS.
- Envelope encryption used; plaintext data key not left on disk.
- Per-tenant keys used; cryptographic erasure demonstrated.
- Integrity verified with hashing / hash chain.

Conclusion

Across both sessions, the lab moved from doing cryptography by hand to seeing how a cloud KMS manages it at scale. Session A established the fundamentals: AES for fast bulk encryption, RSA for asymmetric encryption and signatures, and TLS for protecting data in motion. Session B showed why key management, not the algorithm, is the real security control — envelope encryption kept the master key's exposure minimal, per-tenant keys kept one tenant's compromise from affecting another, and cryptographic erasure turned key deletion into a provable, immediate way to make data permanently unrecoverable. The hashing exercises in Task 7 rounded this out by showing that confidentiality (encryption) and integrity (hashing) are separate concerns that both matter for data protection.
