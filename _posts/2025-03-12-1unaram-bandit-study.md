---
title: "[Linux] Bandit Study Write-Up (1unaram)"
excerpt: "2025-1학기 Linux Bandit 스터디 Write-Up"
author: 1unaram
categories:
    - study
tags:
    - [linux, bandit]
date: 2025-03-12
last_modified_at: 2025-03-12
---

⚙ **Environment: WSL2 Ubuntu 20.04.4 LTS**
{: .notice--info }

<br>

# #Level 0 ~ Level 4

---

## Level 0

```shell
ssh bandit0@bandit.labs.overthewire.org -p 2220
...
bandit0@bandit.labs.overthewire.org's password: bandit0
```

<br>

### ssh

SSH(Secure Shell)은 네트워크 상의 다른 컴퓨터에 로그인하여 명령을 실행하고 파일을 전송할 수 있는 프로토콜을 말한다.

<br>

-   `ssh {user_name}@{server_ip}` : 기본 접속
-   `ssh {user_name}@{server_ip} -p {port_number}` : 특정 포트 접속

<br>

## Level 0 -> Level 1
