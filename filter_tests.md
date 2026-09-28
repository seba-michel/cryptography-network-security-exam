# Firewall Test Evidence

## 1. Laboratory Information

The tests were performed only in the authorized laboratory environment.

Replace the following placeholders with the values supplied by the assessor:

```text
Records Server IP:       <SERVER_IP>
Guest Network/Subnet:    <GUEST_SUBNET>
Staff Network/Subnet:    <STAFF_SUBNET>
Authorized Service Port: <SERVICE_PORT>
```

Do not invent these values.

---

## 2. Test 1 — Authorized Staff Connection

### Purpose

Verify that an authorized staff computer can access the assessor-specified service.

### Source

`<AUTHORIZED_STAFF_IP>`

### Destination

`<SERVER_IP>:<SERVICE_PORT>`

### Command

```bash
nc -vz <SERVER_IP> <SERVICE_PORT>
```

### Expected Result

The connection should be permitted.

### Actual Result

Paste the actual terminal output here:

```text
[PASTE ACTUAL OUTPUT HERE]
```

### Result

`[PASS/FAIL — complete after testing]`

---

## 3. Test 2 — Guest Network Connection

### Purpose

Verify that the guest network cannot access the records server/service.

### Source

`<GUEST_CLIENT_IP>`

### Destination

`<SERVER_IP>:<SERVICE_PORT>`

### Command

```bash
nc -vz <SERVER_IP> <SERVICE_PORT>
```

### Expected Result

The connection should be blocked.

### Actual Result

```text
[PASTE ACTUAL OUTPUT HERE]
```

### Result

`[PASS/FAIL — complete after testing]`

---

## 4. Test 3 — Other Unauthorized Inbound Connection

### Purpose

Verify that other inbound access to the specified service is blocked.

### Source

`<UNAUTHORIZED_SOURCE_IP>`

### Destination

`<SERVER_IP>:<SERVICE_PORT>`

### Command

```bash
nc -vz <SERVER_IP> <SERVICE_PORT>
```

### Expected Result

The connection should be blocked.

### Actual Result

```text
[PASTE ACTUAL OUTPUT HERE]
```

### Result

`[PASS/FAIL — complete after testing]`

---

## 5. Test Summary

| Test | Expected Result | Actual Result | Status |
|---|---|---|---|
| Authorized staff connection | Allowed | [Complete after test] | [PASS/FAIL] |
| Guest connection | Blocked | [Complete after test] | [PASS/FAIL] |
| Other inbound connection | Blocked | [Complete after test] | [PASS/FAIL] |

## 6. Notes

All firewall testing must be performed in the authorized laboratory environment.

Actual commands and results should be recorded after testing.
