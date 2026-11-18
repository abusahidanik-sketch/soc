# Lab Report: Log Analysis with CLI Tools

**Week 2 Lab — Linux Command Line (`grep`, `awk`, `sed`, `cut`, `sort`, `uniq`) on Ubuntu VM**  
**ID:** `2404002`

---

## Summary of Key Findings

| Metric | Value |
| --- | --- |
| Log File | `access.log` (2.3 MB) |
| Total HTTP Requests | 10,000 |
| Unique Client IPs | 1,753 |
| Unique Requested URLs | 1,498 |
| Total Bandwidth Transferred | 2,620.01 MB (~2.6 GB) |
| 404 Not Found Responses | 213 (~2.1%) |
| Suspicious IPs Identified | 36 (`suspicious_ips.txt`) |
| Confirmed Nikto / SQLi / XSS / Path Traversal | 0 |

---

## Part 1: Understanding Apache Log Format

### Step 2.1 — Create Working Directory
```bash
mkdir -p ~/soc-labs/week3 && cd ~/soc-labs/week3 && pwd
```
- **Output:** `/home/whoami/soc-labs/week3`
- **Purpose:** Creates the working directory `~/soc-labs/week3` (`-p` creates parent folders if needed without error), moves into it with `cd`, and prints the current path with `pwd`.
- **Significance:** Keeps all lab evidence and output files (`access.log`, `unique_ips.txt`, `urls.txt`, `suspicious_ips.txt`) organized in one place.

### Step 2.2 — Download Sample Log File
```bash
wget "https://raw.githubusercontent.com/elastic/examples/master/Common%20Data%20Formats/apache_logs/apache_logs" -O access.log; ls -lh access.log
```
- **Output:** `-rw-r--r-- 1 whoami whoami 2.3M Nov  3 10:07 access.log`
- **Purpose:** Downloads the sample Apache access log from the Elastic examples repository as `access.log` and checks its human-readable size.
- **Significance:** Confirms the 2.3 MB evidence file is available locally before analysis.

### Step 2.3 — Verify the File (`ls -lh`)
```bash
ls -lh access.log
```
- **Output:** `-rw-r--r-- 1 whoami whoami 2.3M Nov  3 10:07 access.log`
- **Purpose:** Lists the file in long format with human-readable size.
- **Significance:** Non-zero file size (2.3 MB) with read/write ownership confirms the download succeeded and the log is not empty.

### Step 2.4 — View First 5 Log Lines (`head`)
```bash
head -5 access.log
```
- **Output:** First 5 lines show `GET` requests from `83.149.9.216` on `17/May/2015` returning status `200` for Kibana/Logstash presentation assets (e.g., `kibana-search.png`, 203,023 bytes).
- **Purpose:** Inspects Apache Combined Log Format fields.
- **Significance:** Identifies field positions needed for `awk`: `$1` = Client IP, `$4` = Timestamp, `$6` = HTTP Method, `$7` = URL, `$9` = Status Code, `$10` = Response Bytes.

---

## Part 2: Basic Log Analysis Commands

### Exercise 1 — Count Total Requests
```bash
wc -l access.log
```
- **Output:** `10000 access.log`
- **Significance:** Establishes the baseline of 10,000 HTTP requests for all percentages.

### Exercise 2 — Extract, Sort, Deduplicate, and Count Unique IPs
- **(a) Extract IPs:** `awk '{print $1}' access.log | head -10` → First 10 lines are all `83.149.9.216` (multiple assets loaded by one client).
- **(b) Sort IPs:** `awk '{print $1}' access.log | sort | head -10` → Groups identical IPs together (`1.22.35.226`, `100.2.4.116`, etc.), required before `uniq`.
- **(c) Remove duplicates:** `awk '{print $1}' access.log | sort | uniq | head -10` → Lists each IP once (`1.22.35.226`, `100.2.4.116`, `100.43.83.137`, ...).
- **(d) Count unique IPs:** `awk '{print $1}' access.log | sort | uniq | wc -l` → **`1753`**
- **(e) Count with `sort -u`:** `awk '{print $1}' access.log | sort -u | wc -l` → **`1753`** (more efficient one-step method).

### Exercise 3 — Top 10 Talkers
```bash
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -10
```
| Requests | Client IP |
| ---: | --- |
| 482 | `66.249.73.135` |
| 364 | `46.105.14.53` |
| 357 | `130.237.218.86` |
| 273 | `75.97.9.59` |
| 113 | `50.16.19.13` |
| 102 | `209.85.238.199` |
| 99 | `68.180.224.225` |
| 84 | `100.43.83.137` |
| 83 | `208.115.111.72` |
| 82 | `198.46.149.143` |

- **Significance:** `66.249.73.135` (482 requests) falls in Googlebot's IP range (likely legitimate crawling); other high-volume IPs should be reviewed for scraping or abusive traffic.

### Exercise 4 — HTTP Status Codes & 404 Errors
- **(a) Count 404 with `grep`:** `grep " 404 " access.log | wc -l` → **`213`** (~2.1% of requests)
- **(b) Count 404 with `awk`:** `awk '$9 == 404' access.log | wc -l` → **`213`** (more accurate as it checks column `$9` directly)
- **(c) All status codes:** `awk '{print $9}' access.log | sort | uniq -c | sort -rn`

| Status Code | Count | Meaning |
| --- | ---: | --- |
| `200` | 9,126 | OK |
| `304` | 445 | Not Modified |
| `404` | 213 | Not Found |
| `301` | 164 | Moved Permanently |
| `206` | 45 | Partial Content |
| `500` | 3 | Internal Server Error |
| `416` | 2 | Range Not Satisfiable |
| `403` | 2 | Forbidden |

- **Significance:** Most traffic succeeded; 404s indicate missing or probed paths, 403s show denied access, and the 3 server errors (`500`) merit review.

### Exercise 5 — Top URLs Causing 404
```bash
awk '$9 == 404 {print $7}' access.log | sort | uniq -c | sort -rn | head -5
```
| Count | Requested URL |
| ---: | --- |
| 61 | `/files/logstash/logstash-1.3.2-monolithic.jar` |
| 32 | `/presentations/logstash-puppetconf-2012/images/office-space-printer-beat-down-gif.gif` |
| 6 | `/wp/wp-admin/` |
| 6 | `/wp-login.php?action=register` |
| 6 | `/wp-login.php` |

- **Significance:** The `.jar` and `.gif` 404s are broken links, whereas `/wp/wp-admin/` and `/wp-login.php` probes indicate automated bot reconnaissance for WordPress admin panels.

---

## Part 3: Advanced Pattern Matching with `grep`

### Exercise 6 — Nikto Scanner Detection
- **(a)** `grep -i "nikto" access.log | wc -l` → **`0`**
- **(b)** `grep -i "nikto" access.log | head -5` → *(no output)*
- **(c)** `grep -i "nikto" access.log | awk '{print $1}' | sort -u` → *(no output)*
- **Significance:** No Nikto vulnerability scanner activity was found in this log.

### Exercise 7 — SQL Injection Pattern Detection
- **(a) Broad SQL keywords:** `grep -iE "(union|select|insert|update|delete|drop|exec|script)" access.log | wc -l` → **`124`**
  - *Analysis:* False positives — mostly from `script` (118, e.g., `coffee-script.js`, `/scripts/`) and `drop` (5); `union` = 0 and `select` = 0.
- **(b) Encoded SQL patterns:** `grep -E "(%27|%20union|%20select)" access.log` → **3 lines** matched `%27` (2 noisy/spam-like requests from `94.153.9.168` and 1 harmless referer `New_multiboxer%27s_guide` from `24.11.96.184`). None contained `UNION` or `SELECT`.
- **(c) UNION/SELECT URLs:** `grep -iE "(union|select)" access.log | awk '{print $1, $7}' | head -10` → *(no output)*
- **(d) SQL attempts by IP:** `grep -iE "(union|select)" access.log | awk '{print $1}' | sort | uniq -c | sort -rn` → *(no output)*
- **Significance:** No confirmed SQL injection attempts; illustrates why raw keyword counts must always be manually verified.

### Exercise 8 — XSS Attempt Detection
- **(a)** `grep -iE "(<script|javascript:|onerror=|%3Cscript)" access.log` → *(no output)*
- **(b)** `grep -iE "(<script|javascript:|onerror=|%3Cscript)" access.log | wc -l` → **`0`**
- **(c)** `grep -iE "(<script|javascript:|onerror=)" access.log | awk '{print $1}' | sort | uniq -c | sort -rn` → *(no output)*
- **Significance:** No XSS attempts detected.

### Exercise 9 — Directory Traversal Detection
- **(a)** `grep -E "(\.\./|\.\.%2[Ff])" access.log` → *(no output)*
- **(b)** `grep -E "(\.\./|\.\.%2[Ff])" access.log | wc -l` → **`0`**
- **Significance:** No directory traversal attempts detected.

---

## Part 4: Advanced Analysis with `awk`

### Exercise 10 — Traffic by Hour
```bash
awk '{print $4}' access.log | cut -d: -f2 | sort | uniq -c | sort -rn
```
- **Output:** Busiest hours: `14:00` (498), `15:00` (496), `19:00` (493); Quietest hour: `08:00` (345).
- **Significance:** Traffic is relatively steady across the day with no sudden spike suggesting an automated burst or DDoS attack.

### Exercise 11 — HTTP Request Methods
```bash
awk '{print $6}' access.log | tr -d '"' | sort | uniq -c | sort -rn
```
- **Output:** `GET`: 9,952 | `HEAD`: 42 | `POST`: 5 | `OPTIONS`: 1
- **Significance:** Almost entirely read-only `GET` traffic; no dangerous methods (`PUT`, `DELETE`, `TRACE`) observed.

### Exercise 12 — Investigating POST Requests
- **(a)** `awk '$6 == "\"POST"' access.log | awk '{print $1}' | sort -u` → `37.115.186.244`, `78.173.140.106`, `91.236.74.121`
- **(b)** `awk '$6 == "\"POST" {print $1}' access.log | sort -u` → Same 3 IPs (single-awk version)
- **(c)** `awk '$6 == "\"POST" {print $1, $7, $9}' access.log | head -10`
  - `37.115.186.244` → `/blog/geekery/xvfb-firefox` (`200`)
  - `78.173.140.106` → `/blog/geekery/pyblosxom-mdate-vim-hack.html/trackback/` (`404`, 3 requests — typical of trackback/comment spam bots)
  - `91.236.74.121` → `/projects/xdotool/` (`200`)

### Exercise 13 — Bandwidth Analysis
- **(a) Total bandwidth:** `awk '{sum += $10} END {print sum/1024/1024 " MB"}' access.log` → **`2620.01 MB`**
- **(b) Top 10 IPs by bandwidth:** `awk '{bytes[$1] += $10} END {for (ip in bytes) print ip, bytes[ip]/1024/1024 " MB"}' access.log | sort -k2 -rn | head -10`
  1. `68.180.224.225` — 160.344 MB
  2. `94.23.164.135` — 155.401 MB
  3. `190.153.25.242` — 105.032 MB
  4. `100.2.4.116` — 103.636 MB
  5. `88.198.255.242` — 103.6 MB
  6. `184.154.149.126` — 103.582 MB
  7. `66.249.73.135` — 72.0029 MB
  8. `117.28.234.67` — 66.0043 MB
  9. `82.200.166.110` — 62.2365 MB
  10. `192.95.12.193` — 51.8587 MB

---

## Part 5: Text Transformation with `sed`

### Exercise 14 — Save and Verify `unique_ips.txt`
```bash
awk '{print $1}' access.log | sort -u > unique_ips.txt
wc -l unique_ips.txt; head unique_ips.txt
```
- **Output:** `1753 unique_ips.txt` — clean one-IP-per-line list matching the unique IP count.

### Exercise 15 — Anonymize IPs with `sed`
- **(a) First regex (flawed):** `sed 's/\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}/\1XXX/' access.log | head -5`
  - *Result:* Incorrectly outputs `9.XXX` because `\1` captures only the last repeated octet group.
- **(b) Simpler regex (working):** `sed 's/\.[0-9]*\( \)/\.XXX\1/' access.log | head -5`
  - *Result:* Correctly masks the final octet (`83.149.9.216` → `83.149.9.XXX`) for privacy-safe log sharing.

### Exercise 16 — Extract URLs and Filter Server-Side Scripts
- **(a–b) Save & verify `urls.txt`:**
  ```bash
  awk '{print $7}' access.log | sort -u > urls.txt
  wc -l urls.txt; head -5 urls.txt
  ```
  - *Output:* `1498 urls.txt` (`/`, `//favicon.ico`, `/?N=A&page=21`, `/?flav=atom`, `/?flav=rss20`).
- **(c) Filter `.php`, `.asp`, `.jsp` URLs:**
  ```bash
  awk '{print $7}' access.log | grep -E "\.(php|asp|jsp)$" | sort -u
  ```
  - *Output:* `/admin.php`, `/administrator/index.php`, `/wp-login.php` (all returned `404`, confirming admin-panel probing).

---

## Part 6: Creating the Analysis Report (Deliverables)

### Step 17 (a) — Build `suspicious_ips.txt`
```bash
grep -iE "(wp-login|wp-admin|admin\.php|administrator|/scripts//%22|trackback)" access.log | awk '{print $1}' | sort -u > suspicious_ips.txt; wc -l suspicious_ips.txt; head suspicious_ips.txt
```
- **Output:** `36 suspicious_ips.txt` (includes `129.121.176.228`, `130.185.72.6`, `144.76.194.187`, `144.76.95.39`, `173.236.32.219`, `183.91.14.219`, `184.154.137.213`, `188.165.243.45`, `192.185.81.134`, `192.185.83.181`, etc.).
- **Significance:** Captures 36 unique source IPs responsible for admin/login probing, unusual `/scripts//%22` scanning paths, and trackback spam — candidates for blocking or monitoring.

### Step 17 (b) — Verify Deliverable Files
```bash
ls -lh unique_ips.txt suspicious_ips.txt urls.txt
```
- **Output:**
  - `suspicious_ips.txt` — 516 B
  - `unique_ips.txt` — 25 KB
  - `urls.txt` — 58 KB
