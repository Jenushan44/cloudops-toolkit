def parse_ssh_logs(file_path):
  results = []

  with open(file_path, "r") as file: 
    for line in file:
      # .split() splits the string by any whitespace
      words = line.split()

      if len(words) == 0: 
        continue

      if words[0] != "Accepted" and words[0] != "Failed": 
        continue

      username_index = words.index("for")
      username = words[username_index + 1]
    
      ip_index = words.index("from")
      ip = words[ip_index + 1]
    
      result = {"result": words[0], "username": username, "ip": ip}
      results.append(result)

    return results

print(parse_ssh_logs("tests/sample_ssh_logs.txt"))