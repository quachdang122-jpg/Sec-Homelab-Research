# Hướng dẫn dựng lab

Mục tiêu ngày 1–2: 3 máy ảo nói chuyện được với nhau trong `labnet`, Suricata chạy và bắn được
cảnh báo ICMP test.

## 0. Lưu ý trước khi làm

- `labnet` là **Internal Network** của VirtualBox: không có DHCP, không gateway, không ra Internet.
- **Metasploitable2 chỉ có 1 card: Internal Network `labnet`.** Không bao giờ gắn NAT/Bridged.
- Kali và Ubuntu cần Internet **tạm thời** để cài gói → thêm card thứ 2 kiểu NAT, cài xong thì
  tắt (bỏ tick *Cable Connected* hoặc *Enable Network Adapter*).
- Chụp snapshot mỗi máy sau khi cấu hình xong (`clean-setup`).

## 1. Tạo máy ảo

| Máy | RAM | CPU | Adapter 1 | Adapter 2 (tạm) |
|---|---|---|---|---|
| Kali | 4096 MB | 2 | Internal `labnet` | NAT (để cập nhật) |
| Metasploitable2 | 1024 MB | 1 | Internal `labnet` | **— không có —** |
| Ubuntu Server 24.04 | 3072 MB | 2 | Internal `labnet`, Promiscuous **Allow All** | NAT (để cài Suricata) |

Metasploitable2 là file `.vmdk` → tạo VM *Linux / Other Linux (32-bit)* và chọn *Use an existing
virtual hard disk*.

Promiscuous Mode của Ubuntu: *Settings → Network → Adapter 1 → Advanced → Promiscuous Mode:
Allow All*. Có thể làm bằng lệnh (khi VM tắt):

```powershell
VBoxManage modifyvm "Ubuntu-IDS" --nic1 intnet --intnet1 labnet --nicpromisc1 allow-all
VBoxManage modifyvm "Metasploitable2" --nic1 intnet --intnet1 labnet --nic2 none
```

## 2. Đặt IP tĩnh

### Kali — 10.10.10.10
```bash
# Xem tên kết nối gắn với eth0 (card labnet)
nmcli con show
sudo nmcli con mod "Wired connection 1" ipv4.method manual ipv4.addresses 10.10.10.10/24 \
     ipv4.gateway "" ipv4.dns "" ipv4.never-default yes
sudo nmcli con up "Wired connection 1"
```
`never-default yes` để route mặc định vẫn đi qua card NAT (khi đang bật), không đi vào labnet.

### Metasploitable2 — 10.10.10.20 (user/pass mặc định `msfadmin`)
```bash
sudo nano /etc/network/interfaces
```
```
auto eth0
iface eth0 inet static
    address 10.10.10.20
    netmask 255.255.255.0
```
```bash
sudo /etc/init.d/networking restart
```

### Ubuntu Server — 10.10.10.30
`sudo nano /etc/netplan/50-cloud-init.yaml` (tên file có thể khác, xem `ls /etc/netplan`):

```yaml
network:
  version: 2
  ethernets:
    enp0s3:            # labnet — không gateway
      dhcp4: false
      addresses: [10.10.10.30/24]
    enp0s8:            # NAT tạm thời
      dhcp4: true
```
```bash
sudo chmod 600 /etc/netplan/*.yaml
sudo netplan apply
ip -br a
```

### Kiểm tra
Từ Kali: `ping -c 3 10.10.10.20` và `ping -c 3 10.10.10.30` phải thông.
Từ Metasploitable2: `ping -c 2 8.8.8.8` phải **thất bại** (chứng minh cách ly).

## 3. Cài Suricata trên Ubuntu

```bash
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update && sudo apt install -y suricata jq
suricata --build-info | head -n 5
```

Tắt offload trên card bắt gói để Suricata thấy gói gốc:
```bash
sudo ethtool -K enp0s3 gro off lro off
```
(Muốn giữ sau reboot: tạo một systemd service nhỏ hoặc thêm vào `networkd-dispatcher`.)

### Cấu hình `/etc/suricata/suricata.yaml`

Sửa các chỗ sau:

```yaml
vars:
  address-groups:
    HOME_NET: "[10.10.10.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
```

Kali cũng nằm trong `10.10.10.0/24`, nên traffic tấn công là HOME_NET → HOME_NET.
Rule tự viết để nguồn là `any` hoặc IP cụ thể, đừng dùng `$EXTERNAL_NET` — dùng là không bao giờ khớp.

```yaml
af-packet:
  - interface: enp0s3
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  - /etc/suricata/rules/local.rules
```

Tạo file rule riêng và nạp bộ rule cộng đồng (ET Open — làm trong lúc card NAT còn bật):
```bash
sudo mkdir -p /etc/suricata/rules
sudo cp rules/local.rules /etc/suricata/rules/local.rules   # từ repo này
sudo suricata-update
```

Kiểm tra cú pháp cấu hình + rule:
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```
Phải thấy dòng `Configuration provided was successfully loaded`. Nếu rule lỗi, Suricata in
ra số dòng và sid lỗi.

Chạy dịch vụ:
```bash
sudo systemctl enable --now suricata
sudo systemctl status suricata --no-pager
sudo tail -f /var/log/suricata/suricata.log    # chờ "Engine started"
```

Sau khi cài xong: **tắt card NAT (Adapter 2)** của Ubuntu.

## 4. Test rule ICMP

Trên Ubuntu:
```bash
sudo tail -f /var/log/suricata/fast.log
```
Trên Kali:
```bash
ping -c 3 10.10.10.20
```
Kết quả mong đợi trong `fast.log`:
```
11/13/2026-10:15:02.123456  [**] [1:1000001:1] LAB ICMP Echo Request vao HOME_NET [**] [Classification: Misc activity] [Priority: 3] {ICMP} 10.10.10.10:8 -> 10.10.10.20:0
```

Xem bản ghi JSON:
```bash
sudo jq 'select(.event_type=="alert") | {timestamp, src_ip, dest_ip, sig: .alert.signature}' \
     /var/log/suricata/eve.json | tail -n 20
```

Sửa rule xong không cần restart, chỉ cần reload:
```bash
sudo suricatasc -c reload-rules      # hoặc: sudo kill -USR2 $(pidof suricata)
```

## 5. Xử lý sự cố thường gặp

| Triệu chứng | Nguyên nhân hay gặp | Cách xử lý |
|---|---|---|
| Ping Kali → Ubuntu thông nhưng không có alert khi ping Kali → Metasploitable | Chưa bật Promiscuous Allow All | Tắt VM, bật lại option, khởi động lại |
| Không có alert nào | Sai interface trong `af-packet`, hoặc rule file chưa được nạp | Xem `suricata.log`, tìm dòng `rules loaded` / `1 rule files processed` |
| Rule có nhưng không khớp | Dùng `$EXTERNAL_NET` làm nguồn | Đổi sang `any` hoặc IP cụ thể |
| `fast.log` trống nhưng `eve.json` có alert | Output `fast` bị tắt | Bật `- fast: enabled: yes` trong `outputs` |
| Hai máy không ping nhau | Tên Internal Network gõ khác nhau (`labnet` vs `LabNet`) | Tên phải giống hệt nhau |
