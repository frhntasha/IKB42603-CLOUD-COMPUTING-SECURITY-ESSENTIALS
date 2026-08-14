IKB42603 Cloud Computing Security Essentials
Lab 2 Report — Secure Isolation & Multi-Tenancy

Course: IKB42603 Cloud Computing Security Essentials Lab: Lab 2 — Secure Isolation & Multi-Tenancy (Weeks 3–4) CLO Mapping: CLO2 — Construct secure cloud operations that safeguard data integrity

1. Objective

This lab demonstrates compute, network, and storage isolation for a multi-tenant cloud environment using Docker and Kubernetes (via kind). It covers:

Separating tenants into containers and Kubernetes namespaces
Observing the default-open behaviour of shared infrastructure
Enforcing network isolation with a default-deny NetworkPolicy
Enforcing storage/secret isolation with Kubernetes RBAC
Demonstrating data remanence and secure deletion

2. Setup — Cluster with Policy Enforcement

A kind cluster (ccse-lab2) was created with the default CNI disabled so that Calico could be installed instead, since Calico is required for NetworkPolicy objects to actually be enforced (the default kind network does not enforce policies).

cat <<EOF | kind create cluster --name ccse-lab2 --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF

Calico was then applied to provide policy-enforcing networking, and confirmed ready via rollout status:

kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s

3. Task 1 — Two Tenants on One Cluster

Two namespaces, tenant-a and tenant-b, were created to simulate two customers sharing the same physical cluster. An nginx deployment was created and exposed as a ClusterIP service in each.

kubectl create namespace tenant-a
kubectl create namespace tenant-b
kubectl -n tenant-a create deployment web --image=nginx
kubectl -n tenant-b create deployment web --image=nginx
kubectl -n tenant-a expose deployment web --port=80
kubectl -n tenant-b expose deployment web --port=80
kubectl get pods,svc -n tenant-a

Result: pod web Running, service web assigned ClusterIP 10.96.250.225.

Despite sharing the same underlying cluster, each tenant now has its own pod and service, separated at the namespace level.

4. Task 2 — Observe the Default-Open Risk

To test whether namespaces alone provide network isolation, a probe pod in tenant-a was used to reach tenant-b's service IP (10.96.108.57).

kubectl get svc web -n tenant-b -o jsonpath='{.spec.clusterIP}'; echo
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://10.96.108.57 -o /dev/null -w 'HTTP %{http_code}\n'

Result: HTTP 200

The probe pod in tenant-a successfully reached the service in tenant-b. This confirms that Kubernetes namespaces are an organisational/RBAC boundary, not a network boundary — by default, any pod on the flat cluster network can route to any other pod or service regardless of namespace. On shared multi-tenant infrastructure this is dangerous: without explicit segmentation, one tenant's workload can freely probe, connect to, or attack another tenant's workload.

5. Task 3 — Contain the Noisy Neighbour (Resource Quotas)

A ResourceQuota was applied to tenant-a to cap the CPU, memory, and pod count it can consume, preventing it from exhausting shared node capacity.

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-a-quota
  namespace: tenant-a
spec:
  hard:
    requests.cpu: "1"
    requests.memory: 512Mi
    pods: "5"
EOF
kubectl describe resourcequota tenant-a-quota -n tenant-a

Result: quota created — pods 1/5, requests.cpu 0/1, requests.memory 0/512Mi.

Show Image

6. Task 4 — Default-Deny Network Isolation

A default-deny-ingress NetworkPolicy was applied to tenant-b, denying all inbound traffic to every pod in that namespace unless explicitly allowed.

cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-b
spec:
  podSelector: {}
  policyTypes: [Ingress]
EOF

Re-running the same probe from Task 2 initially failed with a ResourceQuota admission error (must specify requests.cpu for: probe; requests.memory for: probe), because the ad-hoc probe pod didn't declare the resource requests required by the tenant-a-quota from Task 3. This is a useful example of layered controls — the pod was blocked by compute quota admission before the network policy was even reached.

To isolate and verify the network control specifically, the quota was removed temporarily, the probe was re-run, and the quota was then re-applied:

kubectl delete resourcequota tenant-a-quota -n tenant-a
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://10.96.108.57 -o /dev/null -w 'HTTP %{http_code}\n'

Result: HTTP 000 (connection could not be established / timed out)

Show Image

Before/after comparison:

Stage	Result
Before NetworkPolicy (Task 2)	HTTP 200 — reachable
After NetworkPolicy (Task 4)	HTTP 000 — blocked

This before/after pair is the clearest evidence that the default-deny policy is actively enforced by Calico. The tenant-a-quota ResourceQuota was re-applied afterwards to restore the compute isolation control.

7. Task 5 — Storage & Secret Isolation

A Secret was created in each tenant namespace to represent tenant-specific confidential data. A service account, Role, and RoleBinding scoped to tenant-a only were then created so that app-a could read secrets in its own namespace but not in tenant-b.

kubectl -n tenant-a create secret generic data --from-literal=value=SECRET_A
kubectl -n tenant-b create secret generic data --from-literal=value=SECRET_B
kubectl -n tenant-a create serviceaccount app-a
kubectl -n tenant-a create role reader --verb=get --resource=secrets
kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a
SA=system:serviceaccount:tenant-a:app-a
kubectl auth can-i get secrets -n tenant-a --as=$SA
kubectl auth can-i get secrets -n tenant-b --as=$SA

Result:

kubectl auth can-i get secrets -n tenant-a --as=$SA → yes
kubectl auth can-i get secrets -n tenant-b --as=$SA → no

This confirms that RBAC correctly scopes app-a to read secrets only within tenant-a, and denies it access to tenant-b's secrets even though both namespaces share the same cluster.

8. Task 6 — Data Remanence & Secure Deletion

A Docker volume was used to demonstrate that a normal delete can leave recoverable data behind, and that a secure wipe (overwrite-before-delete) mitigates this.

docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; rm /data/phi.txt; \
  grep -a SENSITIVE /data/* 2>/dev/null; echo scan-done'

docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE > /data/phi2.txt; sync; \
  dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; rm /data/phi2.txt; echo wiped'

Result: After the standard rm, the grep -a SENSITIVE scan found no plaintext match in this run (scan-done, no matching line). This shows remanence is probabilistic — it depends on filesystem behaviour and whether storage blocks are reused or overwritten on delete, so it cannot be relied upon. The secure-wipe step explicitly overwrites the file's bytes with zeroes (dd if=/dev/zero ... conv=notrunc) before deleting, which removes the sensitive content regardless of what the filesystem does with the freed blocks (wiped).

9. Short-Answer Questions

Q1. Why can containers in different namespaces reach each other by default, and why is that dangerous in multi-tenant cloud?

Kubernetes namespaces mainly provide organisational separation and a scope for RBAC and resource quotas — they are not a network boundary by themselves. All pods sit on one flat cluster network, so any pod can route to any other pod's or service's IP regardless of namespace, unless a NetworkPolicy (enforced by a CNI like Calico) says otherwise. Task 2 demonstrated this directly: a probe pod in tenant-a reached tenant-b's service and got HTTP 200. On a shared multi-tenant cluster this is dangerous because, without explicit segmentation, one tenant's workload — or an attacker who compromises it — could scan, connect to, or attack another tenant's workload on the same infrastructure, breaking the isolation customers expect between unrelated tenants.

Q2. Explain the default-deny principle and how your NetworkPolicy implements it.

Default-deny means blocking all traffic by default and only permitting the specific, explicitly-approved connections that are actually needed ("deny by default, permit by exception"), rather than trying to allow everything and block known-bad traffic after the fact. In Task 4, the default-deny-ingress policy applies this to tenant-b using an empty podSelector: {} (meaning it applies to every pod in the namespace) and policyTypes: [Ingress] with no ingress rules defined. Because Calico enforces this, no inbound traffic is allowed into any pod in tenant-b — including from tenant-a — unless a future policy explicitly permits a specific source, which matches the HTTP 200 → HTTP 000 result observed before and after the policy was applied.

Q3. How do virtual machines and containers differ in isolation strength? When would you add a VM boundary?

Containers share the host operating system's kernel and are separated from each other using kernel features such as namespaces, cgroups, and capabilities. This gives good process and resource separation, but because all containers on a node share one kernel, a kernel vulnerability or container-escape bug can potentially let one tenant's workload affect another tenant's container or the underlying host — a comparatively thinner trust boundary. Virtual machines instead isolate at the hardware-virtualisation layer: each VM runs its own guest kernel on top of a hypervisor, which is a stronger and more established isolation boundary since escaping a VM to affect the host or another VM is much harder than a container escape. A VM boundary is worth adding when tenants are mutually untrusted and the impact of an escape would be severe — for example, hosting unrelated customers' regulated or highly sensitive workloads on the same physical node, or running third-party code that hasn't been fully vetted — where the extra isolation strength justifies the additional performance and resource overhead.

Q4. What is data remanence, and why is cryptographic erasure the preferred cloud solution?

Data remanence is the residual representation of data that remains on storage media even after it has been "deleted" through normal means. A standard rm/delete typically only removes the filesystem's pointer to the data; the underlying bytes on disk are not necessarily overwritten and may still be recoverable until that storage block gets reused, as illustrated (probabilistically) in Task 6. In cloud environments this is a bigger problem because the tenant doesn't control the physical disks — storage is virtualised, often replicated across multiple physical drives, and reused/reallocated by the provider, so there's no reliable way to guarantee every physical block has been wiped. Cryptographic erasure solves this without needing physical access: the data is encrypted at rest with a key, and to "erase" the data permanently, only the key needs to be destroyed. Without the key, the remaining ciphertext is computationally infeasible to recover from any copy of the physical media, making this a practical, provider-independent way to guarantee erasure in the cloud.

Q5. Which of the three isolation dimensions (compute, network, storage) did each task exercise?

Task	Isolation Dimension(s)
Task 1 — Two tenants on one cluster	Compute (namespace separation of workloads)
Task 2 — Observe the default-open risk	Network (demonstrates the absence of network isolation)
Task 3 — Resource quotas	Compute (CPU/memory/pod-count limits per tenant)
Task 4 — Default-deny NetworkPolicy	Network (blocks cross-tenant traffic)
Task 5 — Secrets & RBAC	Storage (per-tenant secret access restricted via RBAC)
Task 6 — Data remanence & secure deletion	Storage (secure deletion of data at rest)

10. Security Best-Practices Checklist
 Tenants are separated into distinct namespaces
 A default-deny NetworkPolicy blocks cross-tenant traffic (verified before/after — before: HTTP 200; after: HTTP 000, though the retest initially hit the ResourceQuota admission control first, as noted in Task 4)
 Resource quotas prevent a noisy-neighbour from exhausting shared capacity
 Per-tenant secrets are unreadable by other tenants (RBAC enforced — confirmed via auth can-i)
 Secure deletion / cryptographic erasure is understood for data remanence

11. Conclusion

This lab demonstrated all three dimensions of multi-tenant cloud isolation on a shared kind cluster. Namespaces alone gave organisational and quota-level separation but, as Task 2 showed, did not stop cross-tenant network traffic by default — that required an explicit default-deny NetworkPolicy (Task 4), enforced here via the Calico CNI. Storage isolation was likewise not automatic: per-tenant secrets needed RBAC Role/RoleBinding scoping (Task 5) to stop one tenant's service account from reading another tenant's secrets. Finally, Task 6 showed that deleting a file does not guarantee its bytes are gone from disk, and that in cloud environments cryptographic erasure — rather than relying on physical control of the storage media — is the dependable way to handle data remanence.

12. Cleanup
kind delete cluster --name ccse-lab2
docker volume rm ccse-vol
