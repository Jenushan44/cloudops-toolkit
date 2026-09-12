from parser import parse_ssh_logs

events = parse_ssh_logs("tests/sample_ssh_logs.txt")

def analyze_ssh_logs(events): 

  ip_dict = {}
  accepted_count = 0
  failed_count = 0

  for parsed_result in events: 
    if parsed_result['result'] == 'Accepted': 
      accepted_count += 1
    elif parsed_result['result'] == 'Failed': 
      failed_count += 1
    else: 
      continue

  for parsed_result in events: 
    if parsed_result['ip'] in ip_dict: 
      if parsed_result['result']  == 'Failed': 
        ip_dict[parsed_result['ip']]['failed'] += 1
        ip_dict[parsed_result['ip']]['usernames'].append(parsed_result['username'])
    else: 
      if parsed_result['result'] == 'Failed':
        ip_dict[parsed_result['ip']] = {"failed": 1, "usernames": [parsed_result['username']]}               

  return accepted_count, failed_count, ip_dict

  
print(analyze_ssh_logs(events))
  