from parser import parse_ssh_logs

events = parse_ssh_logs("tests/sample_ssh_logs.txt")

def analyze_ssh_logs(events): 

  accepted_count = 0
  failed_count = 0

  for parsed_result in events: 
    if parsed_result['result'] == 'Accepted': 
      accepted_count += 1
    elif parsed_result['result'] == 'Failed': 
      failed_count += 1
    else: 
      continue

  return accepted_count, failed_count

print(analyze_ssh_logs(events))
  