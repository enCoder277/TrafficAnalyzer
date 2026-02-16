# Advanced Traffic Analyzer

## Overview

This is a Python script `advanced_traffic_analyzer.py` designed to analyze web server access logs in a specified format. It supports filtering by HTTP method, status code (single or range), time range (Unix timestamps), and outputs a top-N list of active IPs. The script processes logs efficiently in two passes: first to find the maximum timestamp (for last 24h calculations), then to collect and aggregate statistics. It handles invalid lines with warnings, validates command-line arguments, and generates a structured report.

Key features:
- Filters: method, status, start/end timestamps
- Statistics: total requests, unique IPs, top-N IPs, method distribution (%), top-5 URLs, total data transferred, error counts (4xx/5xx), average 2xx response size
- Recent activity: unique IPs and requests per hour in the last 24 hours from the latest log entry
- Efficiency: Handles up to 1,000,000 lines with linear time complexity
- Error handling: File access, invalid formats, bad args

The script uses standard libraries like `argparse`, `collections.Counter`, and `datetime` for processing.

## Requirements

- Python 3.6+
- No external dependencies

## Usage

Run the script from the command line, providing the path to the log file as the first argument. Optional filters can be added.

### Examples

1. Basic run (all logs, default top=3):
   ```
   python advanced_traffic_analyzer.py sample_access.log
   ```

2. Filter by HTTP method (e.g., GET only):
   ```
   python advanced_traffic_analyzer.py sample_access.log --method GET
   ```

3. Filter by status code (single or range, e.g., 400-499 for client errors):
   ```
   python advanced_traffic_analyzer.py sample_access.log --status 400-499
   ```

4. Time range filter (Unix timestamps):
   ```
   python advanced_traffic_analyzer.py sample_access.log --start 1718000000 --end 1718007000
   ```

5. Custom top-N IPs (e.g., top 5):
   ```
   python advanced_traffic_analyzer.py sample_access.log --top 5
   ```

6. Combined filters:
   ```
   python advanced_traffic_analyzer.py sample_access.log --method POST --status 200 --start 1718000000 --top 10
   ```

If no valid records match filters, it outputs an empty report with a warning. Invalid log lines are skipped with stderr warnings.

## Algorithmic Complexity

- **Time Complexity**: O(n) overall, where n is the number of log lines. Two linear passes over the file: one to find the max timestamp, another to process and aggregate data using counters and sets.
- **Space Complexity**: O(u + m), where u is the number of unique IPs/URLs/methods (typically much smaller than n), due to use of sets and Counters. Suitable for large files without loading everything into memory.

## Possible Improvements

- Add support for compressed logs (e.g., gzip) using `gzip` module.
- Implement additional filters, like by IP or URL pattern.
- Parallel processing for very large files (e.g., using `multiprocessing` for chunked reading).
- Export report to JSON or CSV for further analysis.
- Unit tests with `unittest` or `pytest` for edge cases.
- Configurable output format (e.g., --json flag).