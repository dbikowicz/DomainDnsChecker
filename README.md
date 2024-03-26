# Domain DNS Analyzer

This Python script checks a list of domains for the presence of SPF, DKIM, and DMARC records. It then generates a CSV file containing both the results and statistical data.

## Dependencies
- dns.resolver
- csv
- argparse

## Usage
python domain_dns_analyzer.py <domain_list_file> [-o <output_file>]

- `<domain_list_file>`: Path to the file containing a list of domains to analyze.
- `-o, --output`: (Optional) Output CSV file name. Default: `new_domain_data.csv`

## Example
```python
python domain_dns_analyzer.py domains.txt -o analysis_results.csv
