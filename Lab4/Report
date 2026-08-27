Lab 4 — Access Control & Network Security

IKB42603 Cloud Computing Security Essentials 

Session A (Week 7) — Authentication & Authorization
Task 1 — Authentication: Password-Protected Service

Set up an nginx service with HTTP Basic Authentication using a bcrypt-hashed password file (htpasswd). Verified that requests without credentials are rejected (401) and requests with valid credentials succeed (200).

Note: Initial config used return 200 inside the location block, which bypassed auth_basic entirely due to nginx's request-processing phases (the return directive executes before the access-phase auth check). Fixed by serving a static index.html file instead, letting auth_basic properly gate access to it.
