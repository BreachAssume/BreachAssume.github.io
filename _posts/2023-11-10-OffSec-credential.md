---
title : "OffSec credential"
date: 2023-11-10 07:23:00 +0530
categories: [Misc]
tags: [OffSec]
---

## <span style="color:lightgreen">OffSec credential</span>

```bash
curl -s -k -X $'POST' \
    -H $'Host: api.accredible.com' -H $'Content-Type: application/json' -H $'Content-Length: 62' \
    --data-binary $'{\"filter_queries\":[{\"field\":\"organization.id\",\"value\":81055}]}' \
    $'https://api.accredible.com/v1/recipient/groups/search' | jq -r "[.hits[]|{course_name: ._source.course_name,count: ._source.credentials_count}]"
```

```bash
[
  {
    "course_name": "OffSec Web Expert (OSWE)",
    "count": 2583
  },
  {
    "course_name": "OffSec Certified Professional (OSCP)",
    "count": 14763
  },
  {
    "course_name": "OffSec Exploit Developer (OSED)",
    "count": 602
  },
  {
    "course_name": "OffSec Certified Expert (OSCE)",
    "count": 1262
  },
  {
    "course_name": "OffSec macOS Researcher (OSMR)",
    "count": 85
  },
  {
    "course_name": "OffSec Experienced Penetration Tester (OSEP)",
    "count": 1724
  },
  {
    "course_name": "OffSec Certified Expert 3 (OSCE3)",
    "count": 324
  },
  {
    "course_name": "OffSec Exploitation Expert (OSEE)",
    "count": 107
  },
  {
    "course_name": "Kali Linux Certified Professional (KLCP)",
    "count": 149
  },
  {
    "course_name": "OffSec Wireless Professional (OSWP)",
    "count": 2387
  },
  {
    "course_name": "OffSec Web Assessor (OSWA)",
    "count": 401
  },
  {
    "course_name": "Network Penetration Testing Essentials",
    "count": 534
  },
  {
    "course_name": "OffSec Defense Analyst (OSDA)",
    "count": 236
  },
  {
    "course_name": "Security Operations Essentials",
    "count": 217
  },
  {
    "course_name": "Web Application Assessment Essentials",
    "count": 133
  }
]
```