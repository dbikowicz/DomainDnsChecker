import dns.resolver
import csv

# Create a resolver object with custom timeout settings
resolver = dns.resolver.Resolver()
resolver.lifetime = 20  # Set the timeout to 20 seconds


# define a function to write the data to a CSV
def write_to_csv(data, csv_file):
    headers = ["Domain", "Has SPF", "Has DKIM", "Has DMARC"]

    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)  # Write headers to the file
        for item in data:
            writer.writerow([item['Domain'], item['HasSpf'], item['HasDkim'], item['HasDmarc']])


# list of common skim selectors to test against
common_dkim_selectors = ['s1', 's2', 's3', 'selector', 'selector1', 'selector2', 'selector3', 'google', 'k1', 'k2', 'k3', 'mx', 'mxvault', 'dkim']

# list to append results to, allowing us to add this data to CSV
results_list = []

# list of domains to test
domain_list = []

# iterate through the list of domains and check for SPF, DKIM, and DMARC
for domain in domain_list:
    results = {
        'Domain': domain,
        'HasSpf': False,
        'HasDkim': False,
        'HasDmarc': False
    }

    # check domain for SPF
    try:
        # resolve txt records from domain
        dns_data = resolver.resolve(domain, 'TXT')
        for record in dns_data:
            if 'v=spf1' in str(record):
                results['HasSpf'] = True

    # catch exceptions if there are no DNS records for the domain
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass

    # check domain for DKIM
    for selector in common_dkim_selectors:
        try:
            # resolve DKIM records
            query = selector + "._domainkey." + domain
            dkim_records = resolver.resolve(query, 'TXT')

            # iterate through the data and decode it to plaintext
            for dns_data in dkim_records:
                for string in dns_data.strings:
                    txt_string = string.decode('utf-8').lower()

                    # check for DKIM and change accordingly
                    if ('k=rsa' in txt_string) or ('dkim1' in txt_string):
                        results['HasDkim'] = True
                        break
            if results['HasDkim']:
                break
        # catch exceptions if there are no DNS records for the domain
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        if results['HasDkim']:
            break

    # check domain for DMARC
    try:
        # obtain DMARC records for the given domain
        query = f"_dmarc.{domain}"
        dmarc_records = resolver.resolve(query, 'TXT')

        # iterate through the data and decode it to plaintext
        for dns_data in dmarc_records:
            for string in dns_data.strings:
                txt_string = string.decode('utf-8').lower()
                # check for DMARC and change accordingly
                if 'v=dmarc1' in txt_string:
                    results['HasDmarc'] = True
                    break

    # catch exceptions if there are no DNS records for the domain
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass

    print(results)
    results_list.append(results)
write_to_csv(results_list, 'new_domain_data.csv')
