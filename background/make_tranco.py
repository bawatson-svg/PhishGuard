import csv

input_file = "Tranco_list.csv"          # change to your real filename
output_file = "tranco-top-10k.txt"

domains = []

with open(input_file, "r", encoding="utf-8") as f:
    reader = csv.reader(f)
    next(reader, None)  # skip header if there is one

    for i, row in enumerate(reader):
        if len(row) < 2:
            continue
        domain = row[1].strip().lower()
        if domain:
            domains.append(domain)

        if len(domains) >= 10000:
            break

with open(output_file, "w", encoding="utf-8") as f:
    f.write("\n".join(domains))

print(f"Saved {len(domains)} domains to {output_file}")