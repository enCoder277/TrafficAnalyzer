import argparse
import sys
import os
from collections import Counter
from typing import Optional, Tuple, List
from datetime import datetime, timezone

ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

def human_readable_bytes(num: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num < 1024 or unit == "TB":
            return f"{num:.2f} {unit}"
        num /= 1024

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def parse_args():
    parser = argparse.ArgumentParser(description="Advanced Web Traffic Analyzer")
    parser.add_argument("logfile", help="Path to access log file")
    parser.add_argument("--method", help="Filter by HTTP method")
    parser.add_argument("--status", help="Filter by status code or range (e.g. 404 or 400-499)")
    parser.add_argument("--start", type=int, help="Start timestamp (unix)")
    parser.add_argument("--end", type=int, help="End timestamp (unix)")
    parser.add_argument("--top", type=int, default=3, help="Top N active IPs (default 3)")
    args = parser.parse_args()

    if not os.path.isfile(args.logfile):
        eprint(f"Error: file not found: {args.logfile}")
        sys.exit(1)
    if not os.access(args.logfile, os.R_OK):
        eprint(f"Error: cannot read file: {args.logfile}")
        sys.exit(1)

    if args.method:
        args.method = args.method.upper()
        if args.method not in ALLOWED_METHODS:
            eprint(f"Error: unsupported HTTP method: {args.method}")
            sys.exit(1)

    args.status_filter = None
    if args.status:
        if "-" in args.status:
            try:
                low, high = args.status.split("-", 1)
                low_i, high_i = int(low), int(high)
                if low_i > high_i:
                    raise ValueError
                args.status_filter = (low_i, high_i)
            except Exception:
                eprint("Error: invalid --status range (use 400-499)")
                sys.exit(1)
        else:
            try:
                code = int(args.status)
                args.status_filter = (code, code)
            except Exception:
                eprint("Error: invalid --status value")
                sys.exit(1)

    if args.start and args.end and args.start > args.end:
        eprint("Error: --start must be <= --end")
        sys.exit(1)

    if args.top <= 0:
        eprint("Error: --top must be positive")
        sys.exit(1)

    return args

def parse_log_line(line: str) -> Optional[Tuple[int, str, str, str, int, int]]:
    parts = line.strip().split()
    if len(parts) != 6:
        return None
    try:
        return (
            int(parts[0]),
            parts[1],
            parts[2].upper(),
            parts[3],
            int(parts[4]),
            int(parts[5])
        )
    except ValueError:
        return None

def matches_filters(record, args) -> bool:
    timestamp, ip, method, url, status, size = record
    if args.method and method != args.method:
        return False
    if args.status_filter:
        low, high = args.status_filter
        if not (low <= status <= high):
            return False
    if args.start and timestamp < args.start:
        return False
    if args.end and timestamp > args.end:
        return False
    return True


class TrafficAnalyzer:
    def __init__(self, top_n: int):
        self.top_n = top_n
        self.total_requests = 0
        self.unique_ips = set()
        self.total_data = 0
        self.ip_counter = Counter()
        self.url_counter = Counter()
        self.method_counter = Counter()
        self.success_count = 0
        self.client_error_count = 0
        self.server_error_count = 0
        self.success_size_sum = 0
        self.recent_ip_counts = Counter()
        self.requests_per_hour = Counter()

    def process_record(self, record, cutoff):
        timestamp, ip, method, url, status, size = record
        self.total_requests += 1
        self.unique_ips.add(ip)
        self.total_data += size
        self.ip_counter[ip] += 1
        self.url_counter[url] += 1
        self.method_counter[method] += 1
        if 200 <= status < 300:
            self.success_count += 1
            self.success_size_sum += size
        elif 400 <= status < 500:
            self.client_error_count += 1
        elif 500 <= status < 600:
            self.server_error_count += 1
        if cutoff and timestamp >= cutoff:
            hour_index = (timestamp - cutoff) // 3600
            if 0 <= hour_index < 24:
                self.requests_per_hour[hour_index] += 1
            self.recent_ip_counts[ip] += 1

    def generate_report(self, args, cutoff) -> str:
        lines: List[str] = []
        lines.append("====== TRAFFIC ANALYSIS REPORT ======\n")

        lines.append("Filter settings:")
        if args.start is None and args.end is None:
            lines.append("- Time range: all time")
        else:
            start_str = str(args.start) if args.start is not None else "none"
            end_str = str(args.end) if args.end is not None else "none"
            lines.append(f"- Time range: {start_str} - {end_str}")
        lines.append(f"- Method filter: {args.method if args.method else 'all methods'}")
        if args.status_filter:
            low, high = args.status_filter
            lines.append(f"- Status filter: {low}-{high}" if low != high else f"- Status filter: {low}")
        else:
            lines.append("- Status filter: all statuses")
        lines.append("")

        lines.append("Basic statistics:")
        lines.append(f"Total requests: {self.total_requests}")
        lines.append(f"Unique IPs: {len(self.unique_ips)}")
        lines.append(f"Total data transferred: {self.total_data} ({human_readable_bytes(self.total_data)})")
        lines.append("")

        lines.append("Request distribution:")
        if self.total_requests == 0:
            lines.append("(no data)")
        else:
            for method, count in sorted(self.method_counter.items(), key=lambda x: x[1], reverse=True):
                pct = count / self.total_requests * 100
                lines.append(f"- {method}: {pct:.1f}%")
        lines.append("")

        lines.append("Performance metrics:")
        lines.append(f"- Successful requests (2xx): {self.success_count}")
        lines.append(f"- Client errors (4xx): {self.client_error_count}")
        lines.append(f"- Server errors (5xx): {self.server_error_count}")
        avg = self.success_size_sum / self.success_count if self.success_count else 0
        lines.append(f"- Average response size (2xx): {avg:.2f} bytes")
        lines.append("")

        lines.append(f"Top {args.top} active IPs:")
        top_ips = self.ip_counter.most_common(args.top)
        if not top_ips:
            lines.append("(no data)")
        else:
            for i, (ip, count) in enumerate(top_ips, 1):
                lines.append(f"{i}. {ip}: {count} requests")
        lines.append("")

        lines.append("Top 5 requested URLs:")
        top_urls = self.url_counter.most_common(5)
        if not top_urls:
            lines.append("(no data)")
        else:
            for i, (url, count) in enumerate(top_urls, 1):
                lines.append(f"{i}. {url}: {count}")
        lines.append("")

        lines.append("Recent activity (last 24h):")
        if cutoff is None:
            lines.append("- Unique IPs: 0")
            lines.append("- Requests per hour (last 24h): []")
        else:
            lines.append(f"- Unique IPs: {len(self.recent_ip_counts)}")
            hour_data = []
            for h in range(24):
                ts = cutoff + h * 3600
                dt = datetime.fromtimestamp(ts, tz=timezone.utc).replace(
                    minute=0, second=0, microsecond=0
                ).strftime("%Y-%m-%dT%H:%MZ")
                hour_data.append(f"[{dt}: {self.requests_per_hour.get(h, 0)}]")
            lines.append(f"- Requests per hour (last 24h): {', '.join(hour_data)}")

        return "\n".join(lines)



def find_max_timestamp(path, args):
    max_ts = None
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed and matches_filters(parsed, args):
                ts = parsed[0]
                if max_ts is None or ts > max_ts:
                    max_ts = ts
    return max_ts


def process_file(path, args, cutoff):
    analyzer = TrafficAnalyzer(args.top)
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            parsed = parse_log_line(line)
            if parsed is None:
                eprint(f"Warning: invalid format at line {line_no}")
                continue
            if matches_filters(parsed, args):
                analyzer.process_record(parsed, cutoff)
    return analyzer



def main():
    args = parse_args()
    max_ts = find_max_timestamp(args.logfile, args)
    if max_ts is None:
        eprint("No valid records matched the filters.")
        analyzer = TrafficAnalyzer(args.top)
        print(analyzer.generate_report(args, None))
        sys.exit(0)
    cutoff = max_ts - 86400
    analyzer = process_file(args.logfile, args, cutoff)
    print(analyzer.generate_report(args, cutoff))

if __name__ == "__main__":
    main()