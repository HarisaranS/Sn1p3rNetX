import json
import os
from datetime import datetime

def generate_json_report(scan_results, output_file=None):
    if not output_file:
        output_file = f"sn1p3rnetx_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
    with open(output_file, 'w') as f:
        json.dump(scan_results, f, indent=4)
        
    print(f"[+] JSON report saved to: {output_file}")
    return output_file
