path = "/var/ossec/etc/rules/local_rules.xml"
content = open(path).read()

old_xss = '<url>%3Cscript|onerror%3D|alert%28|%3Cimg|%3Csvg</url>'
new_xss = ('<url>%3Cscript|onerror%3D|onload%3D|onfocus%3D|onmouseover%3D|alert%28|confirm%28|prompt%28|'
           '%3Cimg|%3Csvg|%3Ciframe|javascript%3A|top%5B|window%5B|document%5B</url>')
assert content.count(old_xss) == 1, f"xss anchor not found once: {content.count(old_xss)}"
content = content.replace(old_xss, new_xss, 1)

old_cmdi = '<url>%3B|%60|%7C|;whoami|;cat |;id|`id`</url>'
new_cmdi = ('<url>%3B|%60|%7C|;whoami|;cat |;id|`id`|%24%28|%26%26|%7C%7C|'
            '%0A|%0D|whoami|/etc/passwd|/etc/shadow</url>')
assert content.count(old_cmdi) == 1, f"cmdi anchor not found once: {content.count(old_cmdi)}"
content = content.replace(old_cmdi, new_cmdi, 1)

open(path, "w").write(content)
print("hardened ok")
