from parser import parse_ssh_logs

events = parse_ssh_logs("tests/sample_ssh_logs.txt")

def analyze_ssh_logs(events, threshold = 5): 

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

    if parsed_result['ip'] in ip_dict: 
      if parsed_result['result']  == 'Failed': 
        ip_dict[parsed_result['ip']]['failed'] += 1
        ip_dict[parsed_result['ip']]['usernames'].add(parsed_result['username'])
    else: 
      if parsed_result['result'] == 'Failed':
        ip_dict[parsed_result['ip']] = {"failed": 1, "usernames": {parsed_result['username']}}               

  for ip in ip_dict: 
    if ip_dict[ip]['failed'] >= threshold: 
      ip_dict[ip]['suspicious'] = True  
    else: 
      ip_dict[ip]['suspicious'] = False  
  

  return accepted_count, failed_count, ip_dict

def terminal_report(login_results):

  accepted_count, failed_count, ip_dict = login_results

  ip_failure_count = len(ip_dict)
  suspicious_ips = []

  for ip in ip_dict: 
    if ip_dict[ip]['suspicious'] == True: 
      suspicious_ips.append(ip)
    else: 
      continue

  print("SSH SECURITY REPORT")
  print("-------------------\n")
  print(f"Successful logins: {accepted_count}")
  print(f"Failed attempts: {failed_count}")
  print(f"Unique failure IPs: {ip_failure_count}\n")
  print("Suspicious Sources")
  print("-------------------\n")  

  for suspicious_ip in suspicious_ips: 
    print(suspicious_ip)
    print(f"Failed attempts: {ip_dict[suspicious_ip]['failed']}")
    print(f"Attempted usernames: {ip_dict[suspicious_ip]['usernames']}")

    if ip_dict[suspicious_ip]['suspicious']: 
      print("Status: SUSPICIOUS")
    else: 
      print("Status: NOT SUSPICIOUS")
  
terminal_report(analyze_ssh_logs(events))