path = "/var/ossec/etc/rules/local_rules.xml"
content = open(path).read()

old = '<url>%3B|%60|%7C|;whoami|;cat |;id|`id`|%24%28|%26%26|&&|%7C%7C|%0A|%0D|whoami|/etc/passwd|/etc/shadow</url>'
new = '<url>%3B|%60|%7C|;whoami|;cat |;id|`id`|%24%28|%26%26|&amp;&amp;|%7C%7C|%0A|%0D|whoami|/etc/passwd|/etc/shadow</url>'
assert content.count(old) == 1, content.count(old)
content = content.replace(old, new, 1)
open(path, "w").write(content)
print("patched with proper XML escaping")
