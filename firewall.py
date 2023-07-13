import requests, csv, subprocess

# source= Abuse CH
response = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt").text

rule = "netsh advfirewall firewall add rule name='BadIP'"
subprocess.run(["Powershell","-Command", rule])

mycsv = csv.reader(filter(lambda x: not x.startswith("#"), response.splitlines()))
for row in mycsv:
    ip = row[1]
    if(ip)!=("dst_ip"):
        print("Added Rule to block:", ip)
        # Blocks inbound Ip Addresses
        rule = "netsh advfirewall firewall add rule name='BadIP' Dir=In Action=Block RemoteIP"+ip
        subprocess.run(["Terminal","-Command", rule])
        # Blocks outbound Ip Addresses
        rule = "netsh advfirewall firewall add rule name='BadIP' Dir=Out Action=Block RemoteIP"+ip
        subprocess.run(["Terminal","-Command", rule])

