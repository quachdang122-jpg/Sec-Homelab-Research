# 01 — Dựng lab, rule test ICMP

Ngày: 2026-11-__
Tấn công: Kali 10.10.10.10 → Mục tiêu: Metasploitable2 10.10.10.20
Giám sát: Suricata 10.10.10.30
ATT&CK: T1018

## Mục tiêu
Dựng 3 máy trong `labnet` (các bước ở [docs/setup.md](../docs/setup.md)).
Kiểm tra Suricata có thấy traffic giữa hai máy khác không — Kali ping Metasploitable2,
Ubuntu không nằm trên đường đi mà vẫn phải ra alert.

## Tấn công
```bash
ping -c 3 10.10.10.20    # -c 3: gửi 3 gói rồi dừng
```

Output:
```
TODO
```

## Dấu vết
- pcap: filter `icmp.type == 8` → 3 Echo Request, kèm 3 Echo Reply.
- Suricata: 3 dòng `[1:1000001:1]` trong fast.log.

```
TODO: dán fast.log + 1 bản ghi eve.json
```

## Phát hiện
```
alert icmp any any -> $HOME_NET any (msg:"LAB ICMP Echo Request vao HOME_NET"; itype:8; classtype:misc-activity; sid:1000001; rev:1;)
```
- Nguồn để `any` chứ không phải `$EXTERNAL_NET`, vì Kali cũng nằm trong HOME_NET.
- `itype:8` chỉ bắt Echo Request, mỗi lần ping ra 1 alert chứ không phải 2.

Rule này ping nào cũng kêu, chỉ dùng để test Suricata chạy đúng. Dùng thật thì phải bắt
ping sweep: 1 nguồn ping nhiều máy trong thời gian ngắn, làm bằng `threshold` theo `by_src`.

Ảnh alert: `images/01-alert.png`

## Phòng chống
- Firewall chặn hoặc giới hạn ICMP Echo từ vùng không tin cậy. Không chặn hết ICMP — type 3 code 4
  cần cho PMTUD.
- Theo dõi ping sweep thay vì từng gói ping.

## ATT&CK
| Tactic    | Technique               | ID    |
|-----------|-------------------------|-------|
| Discovery | Remote System Discovery | T1018 |

## Ghi chú
TODO
