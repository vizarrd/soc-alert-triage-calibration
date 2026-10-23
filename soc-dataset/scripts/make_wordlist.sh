#!/bin/bash
# Build a realistic password wordlist from real common passwords, with the decoy's real password appended.
cat > /tmp/passlist.txt <<'EOF'
123456
password
123456789
12345678
12345
qwerty
abc123
password1
1234567
letmein
football
iloveyou
admin
welcome
monkey
login
princess
solo
dragon
passw0rd
master
hello
freedom
whatever
qazwsx
trustno1
sunshine
Winter2025
EOF
wc -l /tmp/passlist.txt
