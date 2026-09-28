# Risk Assessment

## 1. Introduction

The scenario involves a polytechnic institute that stores student records on a central server and transfers files between two campuses.

The security review identified weak staff passwords, outdated software, unencrypted file transfers, guest network access to the records server, and repeated attempts to reach the server from an unfamiliar external address.

## 2. Assets, Vulnerabilities and Consequences

| Asset | Vulnerability | Possible Consequence |
|---|---|---|
| Student records | Unencrypted file transfers | Student information could potentially be intercepted or exposed |
| Central records server | Guest network access | Unauthorized users could potentially reach the records server |
| Staff accounts | Weak passwords | Staff accounts could potentially be compromised |

## 3. Risk Ranking

Risk is evaluated using likelihood and impact.

Scale:

- 1 = Low
- 2 = Medium
- 3 = High

Risk score:

```text
Risk Score = Likelihood × Impact
```

| Risk | Likelihood | Impact | Score | Reason |
|---|---:|---:|---:|---|
| Guest access to records server | 3 (High) | 3 (High) | 9 | Guest users should not have access to the records server |
| Weak staff passwords | 3 (High) | 3 (High) | 9 | Weak passwords may be easier to compromise |
| Unencrypted file transfers | 2 (Medium) | 3 (High) | 6 | Information could potentially be intercepted during transmission |

## 4. Recommended Controls

| Risk | Recommended Control | Purpose |
|---|---|---|
| Guest access to records server | Firewall rules and network segmentation | Restrict guest access to the records server |
| Weak staff passwords | Strong password policy and multi-factor authentication | Reduce unauthorized account access |
| Unencrypted file transfers | Encrypted file transfer | Protect information during transmission |

## 5. Additional Security Concern

The scenario also identifies outdated software and repeated attempts to reach the server from an unfamiliar external address. These issues should be investigated and addressed through software updates, monitoring and appropriate access controls.

## 6. Conclusion

The main risks identified affect confidentiality and unauthorized access to the institute's information systems. The recommended controls reduce unnecessary network access, improve account protection and protect information during transfer.
