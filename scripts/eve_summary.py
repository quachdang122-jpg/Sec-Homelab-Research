#!/usr/bin/env python3
"""
eve_summary.py — Tóm tắt cảnh báo Suricata từ eve.json (định dạng JSON Lines).

Chỉ dùng thư viện chuẩn, chạy được ngay trên Ubuntu Server.

Ví dụ:
    python3 eve_summary.py /var/log/suricata/eve.json
    python3 eve_summary.py eve.json --top 5 --lab-only
    python3 eve_summary.py eve.json --sid 1000001 --src 10.10.10.10
    sudo tail -n 5000 /var/log/suricata/eve.json | python3 eve_summary.py -
"""
import argparse
import json
import sys
from collections import Counter

LAB_SID_MIN, LAB_SID_MAX = 1000001, 1999999  # dải sid cục bộ; ET Open dùng 2xxxxxx
SEVERITY_NAME = {1: "Cao", 2: "Trung bình", 3: "Thấp"}


def read_alerts(stream, stats):
    """Đọc từng dòng, trả về các bản ghi event_type == 'alert'. Bỏ qua dòng hỏng."""
    for line in stream:
        line = line.strip()
        if not line:
            continue
        stats["lines"] += 1
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            stats["bad"] += 1  # dòng cuối có thể bị cắt dở khi Suricata đang ghi
            continue
        if event.get("event_type") == "alert":
            yield event


def matches(event, args):
    alert = event.get("alert", {})
    sid = alert.get("signature_id")
    if args.sid is not None and sid != args.sid:
        return False
    if args.lab_only and (sid is None or not LAB_SID_MIN <= sid <= LAB_SID_MAX):
        return False
    if args.src and event.get("src_ip") != args.src:
        return False
    if args.dst and event.get("dest_ip") != args.dst:
        return False
    return True


def print_top(title, counter, top):
    print(f"\n== {title} ==")
    if not counter:
        print("  (trống)")
        return
    width = max(len(str(k)) for k, _ in counter.most_common(top))
    for key, count in counter.most_common(top):
        print(f"  {str(key):<{width}}  {count:>6}")


def main():
    parser = argparse.ArgumentParser(description="Tóm tắt cảnh báo Suricata trong eve.json")
    parser.add_argument("path", help="đường dẫn eve.json, hoặc '-' để đọc từ stdin")
    parser.add_argument("--top", type=int, default=10, help="số dòng mỗi bảng (mặc định 10)")
    parser.add_argument("--sid", type=int, help="chỉ lấy cảnh báo của sid này")
    parser.add_argument("--src", help="lọc theo IP nguồn")
    parser.add_argument("--dst", help="lọc theo IP đích")
    parser.add_argument("--lab-only", action="store_true",
                        help=f"chỉ lấy rule tự viết (sid {LAB_SID_MIN}–{LAB_SID_MAX})")
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    stats = Counter()
    by_sig, by_src, by_dst, by_pair, by_sev, by_proto = (Counter() for _ in range(6))
    first_ts = last_ts = None
    total = 0

    try:
        stream = sys.stdin if args.path == "-" else open(args.path, encoding="utf-8", errors="replace")
    except OSError as exc:
        sys.exit(f"Không mở được file: {exc}")

    with stream:
        for event in read_alerts(stream, stats):
            if not matches(event, args):
                continue
            total += 1
            alert = event.get("alert", {})
            src, dst = event.get("src_ip", "?"), event.get("dest_ip", "?")
            by_sig[f"[{alert.get('signature_id')}] {alert.get('signature', '?')}"] += 1
            by_src[src] += 1
            by_dst[dst] += 1
            by_pair[f"{src} -> {dst}"] += 1
            sev = alert.get("severity")
            by_sev[f"{sev} ({SEVERITY_NAME.get(sev, '?')})"] += 1
            by_proto[event.get("proto", "?")] += 1
            ts = event.get("timestamp")
            if ts:
                # ISO 8601 cùng múi giờ → so sánh chuỗi là đủ
                first_ts = ts if first_ts is None or ts < first_ts else first_ts
                last_ts = ts if last_ts is None or ts > last_ts else last_ts

    print("=== TÓM TẮT CẢNH BÁO SURICATA ===")
    print(f"Dòng đã đọc     : {stats['lines']}  (lỗi JSON bỏ qua: {stats['bad']})")
    print(f"Số cảnh báo     : {total}")
    if first_ts:
        print(f"Khoảng thời gian: {first_ts}  →  {last_ts}")

    print_top("Theo signature", by_sig, args.top)
    print_top("Theo IP nguồn", by_src, args.top)
    print_top("Theo IP đích", by_dst, args.top)
    print_top("Theo cặp nguồn -> đích", by_pair, args.top)
    print_top("Theo mức độ (severity)", by_sev, args.top)
    print_top("Theo giao thức", by_proto, args.top)


if __name__ == "__main__":
    main()
