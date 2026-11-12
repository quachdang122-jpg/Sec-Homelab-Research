# Security Home Lab

Lab an ninh mạng cá nhân, dựng trên VirtualBox, làm trong ~10 ngày.
Mỗi bài tấn công đều có phần dấu vết, cách phát hiện và cách chặn. Phần phát hiện là phần chính.

Toàn bộ lab nằm trong mạng ảo Internal `labnet`, không ra Internet, không chạm mạng thật.
Chỉ tấn công máy trong lab.

## Lab

```
            labnet — Internal Network, 10.10.10.0/24, không Internet

  Kali              Metasploitable2        Ubuntu Server 24.04
  10.10.10.10       10.10.10.20            10.10.10.30
  tấn công          mục tiêu + DVWA        Suricata (promiscuous)
     |                    |                      |
  ---+--------------------+----------------------+---
```

| Máy                 | Vai trò          | RAM  | IP          |
|---------------------|------------------|------|-------------|
| Kali                | Tấn công         | 4 GB | 10.10.10.10 |
| Metasploitable2     | Mục tiêu (+DVWA) | 1 GB | 10.10.10.20 |
| Ubuntu Server 24.04 | Suricata IDS     | 3 GB | 10.10.10.30 |

Ubuntu để card `enp0s3` ở Promiscuous = Allow All nên Suricata thấy cả traffic Kali → Metasploitable2,
không cần nằm giữa đường.

## Repo

```
README.md
docs/setup.md        dựng lab từ đầu
rules/local.rules    rule Suricata tự viết, sid từ 1000001
writeups/NN-ten.md   mỗi bài 1 file
scripts/             script Python đọc eve.json
attack-mapping.md    bảng MITRE ATT&CK
```

## Write-up

| #  | Bài                                         | ATT&CK          | Xong |
|----|---------------------------------------------|-----------------|------|
| 01 | [Dựng lab, rule test ICMP](writeups/01-dung-lab-icmp.md) | T1018 | đang làm |
| 02 | Trinh sát nmap + Wireshark, rule bắt quét cổng | T1046        |      |
| 03 | DVWA — SQL injection                        | T1190           |      |
| 04 | DVWA — XSS                                  | T1059.007       |      |
| 05 | DVWA — command injection                    | T1190, T1059.004|      |
| 06 | Brute-force SSH bằng Hydra, rule threshold  | T1110.001       |      |
| 07 | Khai thác dịch vụ lỗi trên Metasploitable2  | T1210           |      |
| 08 | (tùy chọn) Test bản local website theo OWASP Top 10 | —       |      |

Bài nào cũng theo một khung: mục tiêu → lệnh đã chạy → dấu vết → rule phát hiện → cách chặn → ATT&CK.
Khung trống ở [writeups/00-template.md](writeups/00-template.md).

## Đọc nhanh cảnh báo

```bash
python3 scripts/eve_summary.py /var/log/suricata/eve.json --top 10
python3 scripts/eve_summary.py /var/log/suricata/eve.json --lab-only   # chỉ rule tự viết
```

## Công cụ

Kali, Metasploitable2, DVWA, Suricata, Wireshark, nmap, Hydra, Metasploit, Python 3.
