import os

f = open("Url.csv", "r") # Read URL
url_str = f.readlines()

s = open("/usr/local/etc/suricata/rules/Warning_url.rules", "w")
for i in range (0, len(url_str)) :
		parsing_url =  url_str[i][url_str[i].find("http"):url_str[i].find("\r")]
		url_name = parsing_url.split("/")[2]
		query =  parsing_url.split("/")[3:]
		query_str = "/".join(query)
#		print query_str
		
		
		rules = "alert tcp any any -> any 80 (msg:\"Warning\"; content:\"GET /"+ query_str +" HTTP/1.1\"; content:\"Host: " + url_name + "\"; sid:" + str(i+10000) + "; rev:1;)\n"
		s.write(rules)
#		print parsing_url

s.close()
f.close()
