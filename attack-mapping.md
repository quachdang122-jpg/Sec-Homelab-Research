# MITRE ATT&CK

Kỹ thuật trong lab ánh xạ sang [ATT&CK Enterprise](https://attack.mitre.org/).
Cột "Phát hiện" là sid trong [rules/local.rules](rules/local.rules) hoặc log dùng để bắt.
ID còn để `10000xx` là chưa viết rule. Làm xong bài nào thì vào trang ATT&CK check lại ID.

| Bài | Làm gì                                   | Tactic            | Technique                                | ID        | Phát hiện                    | Xong |
|-----|------------------------------------------|-------------------|------------------------------------------|-----------|------------------------------|------|
| 01  | Ping xem máy nào sống                    | Discovery         | Remote System Discovery                  | T1018     | sid 1000001                  | đang làm |
| 02  | nmap quét cổng, dịch vụ                  | Discovery         | Network Service Discovery                | T1046     | sid 10000xx                  |      |
| 02  | Quét dải IP                              | Reconnaissance    | Active Scanning: Scanning IP Blocks      | T1595.001 | sid 10000xx                  |      |
| 03  | SQLi trên DVWA                           | Initial Access    | Exploit Public-Facing Application        | T1190     | Apache access.log, sid 10000xx |    |
| 04  | XSS trên DVWA                            | Execution         | Command and Scripting Interpreter: JavaScript | T1059.007 | Apache access.log, sid 10000xx | |
| 05  | Command injection trên DVWA              | Execution         | Command and Scripting Interpreter: Unix Shell | T1059.004 | sid 10000xx            |      |
| 06  | Hydra brute-force SSH                    | Credential Access | Brute Force: Password Guessing           | T1110.001 | sid 10000xx (threshold), auth.log | |
| 07  | Khai thác dịch vụ lỗi (vd. vsftpd 2.3.4) | Lateral Movement  | Exploitation of Remote Services          | T1210     | sid 10000xx                  |      |
| 07  | Shell sau khai thác                      | Command and Control | Non-Application Layer Protocol         | T1095     | sid 10000xx                  |      |
