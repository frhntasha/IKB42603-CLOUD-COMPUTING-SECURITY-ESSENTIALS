Lab 4 — Access Control & Network Security

IKB42603 Cloud Computing Security Essentials 

Session A (Week 7) — Authentication & Authorization
Task 1 — Authentication: Password-Protected Service

Set up an nginx service with HTTP Basic Authentication using a bcrypt-hashed password file (htpasswd). Verified that requests without credentials are rejected (401) and requests with valid credentials succeed (200).

Note: Initial config used return 200 inside the location block, which bypassed auth_basic entirely due to nginx's request-processing phases (the return directive executes before the access-phase auth check). Fixed by serving a static index.html file instead, letting auth_basic properly gate access to it.
<img width="772" height="222" alt="task1_evidence" src="https://github.com/user-attachments/assets/ec726100-3733-42cf-bbd0-5ed87e6f47f7" />

Task 2 — MFA / TOTP

Generated a TOTP secret and validated a time-based one-time code, replicating how an authenticator app works. Used pyotp (Python) as a Windows-compatible equivalent to oathtool, since oathtool is a Linux-only package.
<img width="916" height="205" alt="task2_mfa_ok" src="https://github.com/user-attachments/assets/f8845528-5808-4ffd-8ea9-93af5fff4ea5" />

Task 3 — Authorization: RBAC Roles

Created a Kubernetes cluster (kind) with a dev service account restricted to read-only access on pods via a custom Role and RoleBinding. Verified permissions using kubectl auth can-i.
<img width="852" height="207" alt="task3_rbac_can_i" src="https://github.com/user-attachments/assets/827097c9-4ed1-4c0a-9682-e326c542cc5e" />

Task 4 — Network Segmentation (Three-Tier)

Isolated db (Redis) onto a backend-net Docker network, web onto a separate frontend-net, and connected app to both, simulating a three-tier architecture. Confirmed web cannot reach db directly, while app can.

Note: Base image for web/app (nginx, Debian-based) required apt-get instead of apk (Alpine's package manager) to install curl/netcat-traditional.
<img width="941" height="202" alt="task4_segmentation" src="https://github.com/user-attachments/assets/f56f2ff9-beb7-48ce-b6fe-dec38f045ed7" />

Task 5 — Default-Deny Firewall

Applied iptables rules inside a throwaway container: default DROP policy on INPUT, with explicit ACCEPT rules for port 443 and loopback traffic — mirroring the cloud Security Group model.
<img width="705" height="202" alt="task5_iptables_default_deny" src="https://github.com/user-attachments/assets/64aa35b6-160a-44c1-81a8-43509b9fa19a" />

Task 6 — Container / Host Hardening

Ran a hardened container (nginxinc/nginx-unprivileged) as non-root (UID 1000), read-only root filesystem, all Linux capabilities dropped, and no-new-privileges set. Scanned the base nginx:alpine image with Trivy for known HIGH/CRITICAL vulnerabilities.
<img width="902" height="457" alt="task6_hardened_inspect" src="https://github.com/user-attachments/assets/9fdeabae-488a-492b-8b45-f9c09f7bb2b2" />

<img width="1387" height="342" alt="task6_trivy_scan" src="https://github.com/user-attachments/assets/b39033ad-6545-444f-ab5b-86d8717ca1f9" />

Hardening measures applied and attack surface removed:

Measure	Attack it blunts
--user 1000:1000 (non-root)	Container breakout escalating to root on host
--read-only + --cap-drop=ALL	Malware writing/persisting files; capability abuse (e.g. CAP_SYS_ADMIN exploits)
--security-opt no-new-privileges	Privilege escalation via setuid binaries

Trivy scan result: nginx:alpine (Alpine 3.24.1) — 2 vulnerabilities found (HIGH: 2, CRITICAL: 0), no secrets detected.

<img width="486" height="317" alt="verify_rolebinding" src="https://github.com/user-attachments/assets/b2ff8892-05e9-4e43-ac54-fc10c2387bae" />
<img width="605" height="70" alt="verify_capdrop" src="https://github.com/user-attachments/assets/80733d01-8217-4018-9a99-9e4b23d799c8" />

Short-Answer Questions

Q1. Explain the difference between authentication and authorization using Tasks 1 and 3.

Task 1 (HTTP Basic Auth) proves who is making the request — supplying a valid username and password is authentication. Task 3 (RBAC) decides what that identity is permitted to do once verified — the dev service account is authenticated as itself but only authorized to get/list pods, not to create or delete them. Authentication answers "are you who you claim to be?"; authorization answers "are you allowed to do this?"

Q2. Why is MFA so effective, and which attacks does it defeat?

MFA combines two different factor classes — something you know (password) and something you have (a TOTP-generating device or secret). Even if a password is phished, leaked, or reused across services, an attacker still lacks the second factor to complete authentication. This defeats credential stuffing, password-reuse attacks, and most phishing attempts, making it one of the cheapest, highest-impact security controls available.

Q3. How does network segmentation limit the damage of a compromised web server?

By placing the database on a separate Docker network (backend-net) that the web tier isn't connected to, a compromised web container has no network path to db — the isolation happens at the OS/network level, not just through an application-layer rule. Even with full control of the web container, an attacker cannot pivot directly to the data tier, containing the breach to the tier they compromised (defense in depth against lateral movement).

Q4. What does a default-deny firewall policy achieve, and how does it relate to cloud security groups?

A default-deny policy (iptables -P INPUT DROP) blocks all inbound traffic unless a rule explicitly permits it — in this lab, only port 443 and loopback traffic are allowed. This is the exact least-privilege model used by cloud Security Groups / Network Security Groups (AWS, Azure, GCP): nothing is reachable by default, and every open port is a deliberate, auditable exception rather than something left open by omission.

Q5. List the hardening measures you applied and the attack surface each one removes.

Non-root user (--user 1000:1000) — removes the ability for a container breakout to gain root privileges on the host.
Read-only filesystem + all capabilities dropped (--read-only, --cap-drop=ALL) — prevents malware from writing persistent files or abusing Linux capabilities (e.g. CAP_SYS_ADMIN, CAP_NET_RAW) to escalate or pivot.
No new privileges (--security-opt no-new-privileges) — blocks privilege escalation via setuid/setgid binaries even if one exists inside the image.
Vulnerability scanning (Trivy) — surfaces known CVEs in the base image before deployment, allowing patching ahead of exploitation.

Security Best-Practices Checklist
 Service requires authentication (unauthenticated requests rejected)
 MFA / second factor implemented and validated
 Authorization enforced by RBAC (least privilege; unauthorized actions denied)
 Network segmented so the data tier is unreachable from the front tier
 Default-deny firewall with explicit allow rules
 Container hardened: non-root, minimal, capabilities dropped, read-only; image scanned
