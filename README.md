# VT_API_URL
Current as of: 20190509
Use VT_API_URL to bulk scan domains to speed up analysis

Scripts take a CSV of domains.

Deduplicate the list to be nice to Virustotal(VT)

Run Scanner_VT_API_URL.py first to make sure all URLs are submitted to VT

Run Report_VT_API_URL.py second to pull results.
This will also display only domains with a "positives" score greater than one.
Results for all domains will be saved in json format for later use.
Results for positive hits will be saved in ReportResults.log
