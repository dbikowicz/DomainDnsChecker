import dns.resolver
import csv
import argparse

# Create a resolver object with custom timeout settings
resolver = dns.resolver.Resolver()
resolver.lifetime = 20  # Set the timeout to 10 seconds


# define a function to write the data to a CSV
def write_to_csv(data, csv_file):
    headers = ["Domain", "Has SPF", "Has DKIM", "Has DMARC", "Error"]

    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)  # Write headers to the file
        for item in data:
            writer.writerow([item['Domain'], item['HasSpf'], item['HasDkim'], item['HasDmarc'], item['Error']])

def main():
    parser = argparse.ArgumentParser(description='Domain DNS Analyzer')
    parser.add_argument('domain_list_file', help='Path to the file containing a list of domains to analyze')
    parser.add_argument('-o', '--output', default='new_domain_data.csv', help='Output CSV file name')
    args = parser.parse_args()

    # Read domain list from file
    with open(args.domain_list_file) as f:
        domain_list = f.read().splitlines()

    # list of common dkim selectors to test against
    common_dkim_selectors = ['s1', 's2', 's3', 'selector', 'selector1', 'selector2', 'selector3', 'google', 'k1', 'k2', 'k3', 'mx', 'mxvault', 'dkim']

    # list to append results to, allowing us to add this data to CSV
    results_list = []

    # iterate through the list of domains and check for SPF, DKIM, and DMARC
    for domain in domain_list:

        results = {
            'Domain': domain,
            'HasSpf': False,
            'HasDkim': False,
            'HasDmarc': False,
            'Error': ''
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
        except dns.resolver.LifetimeTimeout:
            results['Error'] += 'SPF '
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
            except dns.resolver.LifetimeTimeout:
                results['Error'] += 'DKIM '
                break
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
        except dns.resolver.LifetimeTimeout:
            results['Error'] += 'DMARC'
            pass

        print(results)
        results_list.append(results)


    # initialize counters for stats
    total_spf_domain = total_true_spf = total_dkim_domain = total_true_dkim = total_dmarc_domain = total_true_dmarc = error_free_total = total_all_true = total_all_false = 0

    # calculate stats
    for result in results_list:
        # SPF stats
        if 'SPF' not in result['Error']:
            total_spf_domain += 1
            if result['HasSpf']:
                total_true_spf += 1

        # DKIM stats
        if 'DKIM' not in result['Error']:
            total_dkim_domain += 1
            if result['HasDkim']:
                total_true_dkim += 1

        # DMARC stats
        if 'DMARC' not in result['Error']:
            total_dmarc_domain += 1
            if result['HasDmarc']:
                total_true_dmarc += 1

        # error-free domain count
        if not result['Error']:
            error_free_total += 1

        # all true and all false
        if result['HasSpf'] and result['HasDkim'] and result['HasDmarc'] and not result['Error']:
            total_all_true += 1
        elif not result['HasSpf'] and not result['HasDkim'] and not result['HasDmarc'] and not result['Error']:
            total_all_false += 1

    # calculate percentages
    percentage_true_spf = (total_true_spf / total_spf_domain) * 100 if total_spf_domain != 0 else 0
    percentage_true_dkim = (total_true_dkim / total_dkim_domain) * 100 if total_dkim_domain != 0 else 0
    percentage_true_dmarc = (total_true_dmarc / total_dmarc_domain) * 100 if total_dmarc_domain != 0 else 0
    percentage_all_true = (total_all_true / error_free_total) * 100 if error_free_total != 0 else 0
    percentage_all_false = (total_all_false / error_free_total) * 100 if error_free_total != 0 else 0

    # add blank line to CSV
    results_list.append({
        'Domain': '',
        'HasSpf': '',
        'HasDkim': '',
        'HasDmarc': '',
        'Error': ''
    })

    # append statistics to results_list
    results_list.append({
        'Domain': 'Percentage True',
        'HasSpf': f"{percentage_true_spf:.2f}%",
        'HasDkim': f"{percentage_true_dkim:.2f}%",
        'HasDmarc': f"{percentage_true_dmarc:.2f}%",
        'Error': ''
    })

    results_list.append({
        'Domain': 'Total All True',
        'HasSpf': f"{percentage_all_true:.2f}%",
        'HasDkim': '',
        'HasDmarc': '',
        'Error': ''
    })

    results_list.append({
        'Domain': 'Total All False',
        'HasSpf': f"{percentage_all_false:.2f}%",
        'HasDkim': '',
        'HasDmarc': '',
        'Error': ''
    })

    write_to_csv(results_list, 'new_domain_data.csv')

if __name__ == "__main__":
    main()