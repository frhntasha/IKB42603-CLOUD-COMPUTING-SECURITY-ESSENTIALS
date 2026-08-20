Lab 1: Cloud Account Security, Identity and Access Management

Course: IKB42603 Cloud Computing Security Essentials 
Lab: Lab 1 Topic: Identity governance, least privilege, LocalStack IAM and Kubernetes RBAC
Environment: LocalStack on localhost:4566 and kind Kubernetes cluster ccse-lab1 
Name: frhntasha

Lab Summary // Objective
This report covers two hands-on exercises in cloud identity management:

Using LocalStack to practise core AWS IAM operations — creating users, groups, policies, and access keys, without touching a real AWS account.
Using a local Kubernetes cluster to see access control actually enforced, by defining a Role, binding it to an identity, and testing the boundary with live commands.

Overview
The lab runs across two sessions:

Session A: Cloud identity basics on LocalStack — avoiding root, creating scoped users and groups, managing access keys.
Session B: Kubernetes RBAC, where permissions aren't just declared but actually checked and enforced against a live cluster.

Everything stays local — LocalStack simulates the AWS API on localhost:4566, and kind runs a disposable Kubernetes cluster inside Docker. No real cloud account is touched.

Session A — Cloud Identity with LocalStack
Environment Setup
docker run -d --name localstack \
  -p 4566:4566 \
  -e LOCALSTACK_AUTH_TOKEN=$LOCALSTACK_AUTH_TOKEN \
  localstack/localstack
curl http://localhost:4566/_localstack/health

Explanation: Starts LocalStack in the background on port 4566, the single endpoint all emulated AWS services sit behind. As of this LocalStack version (2026.7.2), the image requires a valid auth token to activate — so the token is passed in as an environment variable before startup, and the health check confirms all services report available once the container finishes booting.

aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1

Explanation: The AWS CLI requires some credentials to run, even against an emulator. LocalStack doesn't validate these values, so placeholder strings are sufficient.

EP='--endpoint-url=http://localhost:4566'
aws $EP sts get-caller-identity

Explanation: The --endpoint-url flag is what redirects the CLI to the local container instead of real AWS. sts get-caller-identity then confirms which identity the CLI is currently operating under.

Output:
{
    "UserId": "000000000000",
    "Account": "000000000000",
    "Arn": "arn:aws:iam::000000000000:root"
}

The repeated 000000000000 is LocalStack's standard placeholder account number — confirmation this ran against the local emulator, not a real AWS account.

Evidence:
<img width="1036" height="347" alt="01-caller-identity" src="https://github.com/user-attachments/assets/6db1146d-b83d-4928-9904-589e3f75df9e" />

Task 1 — Map the Cloud Identity Landscape
Concept	AWS term	Purpose
All-powerful owner	Root user	The identity created with the account itself, with no restrictions on what it can do. Because compromising it means total account takeover, it should be locked away and never used for everyday tasks.
Human/app identity	IAM User	A dedicated identity for one person or application. Giving each actor its own identity means access can be tracked, adjusted, or revoked individually instead of everyone sharing one login.
Permission bundle	IAM Policy	The rulebook itself — a JSON document that spells out exactly which actions are allowed or denied, and on what resources. Nothing is granted until a policy says so.
Collection of users	IAM Group	A container for related users so a policy only needs to be attached once. Add someone to the group and they inherit its access; remove them and it's gone — no per-user edits needed.
Temporary identity	IAM Role	An identity with no permanent credentials attached. A user, app, or service assumes it temporarily and gets short-lived credentials in return — safer than issuing something that never expires.
Task 2 — Create a Least-Privilege Admin
aws $EP iam create-group --group-name Admins
aws $EP iam attach-group-policy --group-name Admins \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws $EP iam create-user --user-name CloudAdmin_frhntasha
aws $EP iam add-user-to-group --group-name Admins \
  --user-name CloudAdmin_frhntasha
aws $EP iam get-group --group-name Admins

Explanation: AdministratorAccess is attached to the Admins group itself, not directly to a user — that's the whole point of the exercise. CloudAdmin_frhntasha is created as a dedicated identity to replace root for day-to-day admin work, then added to the group so it inherits admin access purely through membership. The final get-group call confirms the user actually landed in the group.

Output:

{
    "Users": [
        {
            "Path": "/",
            "UserName": "CloudAdmin_frhntasha",
            "UserId": "AIDAQAAAAAAAFWFARYGGF",
            "Arn": "arn:aws:iam::000000000000:user/CloudAdmin_frhntasha",
            "CreateDate": "2026-08-20T14:51:24.556532+00:00"
        }
    ],
    "Group": {
        "Path": "/",
        "GroupName": "Admins",
        "GroupId": "AGPAQAAAAAAAKS57L43CD",
        "Arn": "arn:aws:iam::000000000000:group/Admins",
        "CreateDate": "2026-08-20T14:50:52.538151+00:00"
    }
}

This confirms CloudAdmin_frhntasha sits inside Admins, drawing its permissions from the group rather than holding them directly.

Evidence:
<img width="1103" height="725" alt="02-admin-group-setup" src="https://github.com/user-attachments/assets/077fd969-1453-4bc7-854b-9723c529a8a1" />

Task 3 — Enforce Least Privilege with a Scoped Policy
aws $EP iam create-user --user-name Analyst_frhntasha
aws $EP iam attach-user-policy --user-name Analyst_frhntasha \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
aws $EP iam list-attached-user-policies --user-name Analyst_frhntasha

Explanation: Analyst_frhntasha represents a teammate who should only be able to read data, never modify it. Only AmazonS3ReadOnlyAccess is attached, so the policy list shows a single read-only policy and nothing broader.

Output:

{
    "AttachedPolicies": [
        {
            "PolicyName": "AmazonS3ReadOnlyAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
        }
    ]
}

Evidence:
<img width="793" height="482" alt="03-analyst-user-policy" src="https://github.com/user-attachments/assets/643c2650-4dcd-4129-a26a-ce6883d89329" />

Report answer — why is the damage limited if the Analyst account is stolen? Analyst_frhntasha only has AmazonS3ReadOnlyAccess — enough to read S3 data and nothing else. If those credentials leaked, an attacker could only view data, not delete, modify, or reach any other AWS service. That's the blast-radius reduction least privilege buys: the compromise stays contained to one narrow capability, instead of turning into full account control the way a stolen admin identity would.

Task 4 — Credential Hygiene & Access Keys
aws $EP iam create-access-key --user-name Analyst_frhntasha
aws $EP iam list-access-keys --user-name Analyst_frhntasha

Explanation: Creates a programmatic access key for Analyst_frhntasha and lists it to note the AccessKeyId and current status (Active).

Output:
{
    "AccessKeyMetadata": [
        {
            "UserName": "Analyst_frhntasha",
            "AccessKeyId": "LKIAQAAAAAAAPGUJMHVR",
            "Status": "Active",
            "CreateDate": "2026-08-20T14:54:20.694619+00:00"
        }
    ]
}

Evidence:
<img width="881" height="297" alt="04b-access-key-rotated" src="https://github.com/user-attachments/assets/0f28a577-50ea-405a-bc66-276cb139c238" />

aws $EP iam update-access-key --user-name Analyst_frhntasha \
  --access-key-id LKIAQAAAAAAAPGUJMHVR --status Inactive
aws $EP iam list-access-keys --user-name Analyst_frhntasha

Explanation: Rotates the key by deactivating it rather than deleting it outright, then confirms the status change. Long-lived access keys are a liability if they leak since they don't expire on their own — rotating them regularly (or preferring short-lived role credentials instead) limits how long a leaked key stays useful to an attacker.

Output:

{
    "AccessKeyMetadata": [
        {
            "UserName": "Analyst_frhntasha",
            "AccessKeyId": "LKIAQAAAAAAAPGUJMHVR",
            "Status": "Inactive",
            "CreateDate": "2026-08-20T14:54:20.694619+00:00"
        }
    ]
}

Evidence:
<img width="1122" height="583" alt="05-kind-cluster-setup" src="https://github.com/user-attachments/assets/1f285d9a-f544-46bc-97dd-4d9f4e56403f" />

Session B — Enforced Access Control with Kubernetes RBAC

LocalStack shows what IAM structures look like, but doesn't actually stop an unauthorised action from being carried out. Kubernetes RBAC does — this session proves that directly.

kind create cluster --name ccse-lab1
kubectl cluster-info --context kind-ccse-lab1
kubectl get nodes

Explanation: kind builds a real, disposable Kubernetes cluster inside Docker, entirely on the local machine — no cloud account involved. The cluster-info and get nodes checks confirm the control plane is responding and the node is Ready before deploying anything.

Output:
NAME                      STATUS   ROLES           AGE   VERSION
ccse-lab1-control-plane   Ready    control-plane   25s   v1.31.0

Evidence:
<img width="515" height="320" alt="06-namespaces-created" src="https://github.com/user-attachments/assets/7ea0ca39-3433-4126-99e7-03a31c5e7635" />

Task 5 — Separate Environments with Namespaces
kubectl create namespace dev
kubectl create namespace prod
kubectl get namespaces

Explanation: Namespaces split one cluster into isolated pockets. Having dev and prod side by side sets up the Task 7 test — proving access granted in one doesn't leak into the other.

Output:

NAME                 STATUS   AGE
default              Active   98s
dev                  Active   15s
kube-node-lease      Active   98s
kube-public          Active   98s
kube-system          Active   98s
local-path-storage   Active   91s
prod                 Active   7s

Evidence:
<img width="728" height="242" alt="07-role-rolebinding-setup" src="https://github.com/user-attachments/assets/4b833591-312a-4ea3-8640-f9d1960afcbf" />

Task 6 — Define a Role and Bind It
kubectl create serviceaccount dev-user -n dev

kubectl create role pod-reader -n dev \
  --verb=get,list,watch --resource=pods

kubectl create rolebinding dev-user-binding -n dev \
  --role=pod-reader --serviceaccount=dev:dev-user

Explanation: The ServiceAccount dev-user stands in for a developer identity, scoped to the dev namespace from the start. The Role pod-reader defines a namespaced permission set limited to read-type verbs on pods — no create, update, or delete. A Role alone grants nothing until bound; the RoleBinding is what connects pod-reader to dev-user, and because RoleBindings are namespace-scoped, the grant stays confined to dev.

Output:

serviceaccount/dev-user created
role.rbac.authorization.k8s.io/pod-reader created
rolebinding.rbac.authorization.k8s.io/dev-user-binding created

Evidence:
<img width="545" height="205" alt="08-auth-can-i-results" src="https://github.com/user-attachments/assets/1f49263e-9c05-402c-b073-f26bed6df7f7" />

Task 7 — Test That Access Control Works
SA=system:serviceaccount:dev:dev-user

kubectl auth can-i list pods -n dev --as=$SA
kubectl auth can-i delete pods -n dev --as=$SA
kubectl auth can-i list pods -n prod --as=$SA

Explanation: kubectl auth can-i --as=<identity> checks what an identity would be allowed to do, without actually performing the action. Running all three together shows the boundary from three angles: what's allowed, which verb is blocked, and which namespace is off-limits.

Results:

list pods -n dev → yes — covered directly by pod-reader.
delete pods -n dev → no — delete was never part of the Role's verb list.
list pods -n prod → no — the RoleBinding never extended past dev.

Evidence:
<img width="728" height="330" alt="09-rolebinding-yaml" src="https://github.com/user-attachments/assets/7fe4962f-e9fa-485e-9032-a743f764fa4a" />

Authentication vs. Authorization: All three checks pass authentication without any issue — Kubernetes has no trouble recognising system:serviceaccount:dev:dev-user as a legitimate identity every time. What differs between the three results is authorization. For list pods -n dev, the Role and RoleBinding line up with what's being requested, so it's approved. For the other two, the identity is still recognised, but nothing in its RBAC configuration covers delete or extends into prod — so it's authorization, not authentication, that refuses the request.

Short-Answer Questions

Q1. Why is attaching policies to groups better than attaching them directly to users? A policy attached to a group applies to every member at once — one edit updates everyone's access together. Attaching per-user means the same change has to be repeated for each person, which gets harder to keep consistent as the number of users grows.

Q2. What is the difference between an IAM User and an IAM Role? A User is a fixed identity with its own long-term credentials, tied to a specific person or application until deleted. A Role has no credentials of its own — something else assumes it temporarily and receives a short-lived token for that session only, so there's no long-term secret sitting around waiting to leak.

Q3. Explain least privilege using the Analyst account, and how it reduces blast radius if compromised. Analyst_frhntasha was only given AmazonS3ReadOnlyAccess — just enough to do its job, nothing more. If those credentials were stolen, the attacker's options are limited to reading S3 data; there's no path to deleting, modifying, or reaching any other part of the account. That containment is exactly what least privilege buys — the compromise stays small instead of escalating into full account control, which is what a leaked admin identity would allow.

Q4. In Kubernetes, what is the difference between a Role and a RoleBinding? A Role only describes permissions — which verbs apply to which resources, within a given namespace. On its own it grants nothing. A RoleBinding is what connects that Role to an actual identity (a user, group, or service account), turning the description into an active grant.

Security Best-Practices Checklist
- Root was never used for day-to-day work — CloudAdmin_frhntasha was created as a dedicated admin identity instead.
- Admin access came through the Admins group rather than being attached to the user directly.
- A scoped-down identity, Analyst_frhntasha, was created with read-only S3 access only.
- An access key was generated, listed, and deactivated to demonstrate rotation.
- Kubernetes RBAC actually blocked both a disallowed verb (delete) and a cross-namespace request (prod).
- dev and prod were kept in separate namespaces so permissions in one couldn't bleed into the other.
  
Conclusion

Across both sessions, the same idea kept resurfacing: identities should only get exactly the access they need, structured in a way that's easy to manage and audit. In LocalStack, that meant attaching admin rights to a group instead of a person, and carving out a separate read-only identity for a lower-trust role. In Kubernetes, the same principle was tested for real — dev-user could read pods in dev and nothing more, with both a disallowed action and a disallowed namespace refused automatically once the Role and RoleBinding were checked. LocalStack showed how the pieces of IAM fit together conceptually; the Kubernetes cluster showed what it looks like when those boundaries are actually enforced.
