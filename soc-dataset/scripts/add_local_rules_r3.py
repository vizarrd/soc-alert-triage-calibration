path = "/var/ossec/etc/rules/local_rules.xml"
content = open(path).read()

addition = '''

<group name="local,web,attack,">
  <rule id="100101" level="12">
    <if_sid>31100,31108</if_sid>
    <url>%3Cscript|onerror%3D|alert%28|%3Cimg|%3Csvg</url>
    <description>Possible Cross-Site Scripting (XSS) attempt in web request.</description>
    <group>attack,xss,gdpr_IV_35.7.d,pci_dss_6.5,</group>
  </rule>

  <rule id="100102" level="14">
    <if_sid>31100,31108</if_sid>
    <url>%7B%7B|__class__|__globals__|__builtins__|__mro__|__subclasses__</url>
    <description>Possible Server-Side Template Injection (SSTI) / RCE attempt in web request.</description>
    <group>attack,ssti,rce,gdpr_IV_35.7.d,pci_dss_6.5,</group>
  </rule>
</group>
'''

content = content.rstrip() + addition
open(path, "w").write(content)
print("appended ok")
