---
title: "[Linux] Bandit Study Write-Up (hyungin0505)"
excerpt: "2025-1학기 Linux Bandit 스터디 Write-Up"
author: hyungin0505
categories:
    - study
tags:
    - [linux, bandit]
date: 2025-03-25
last_modified_at: 2025-03-25
---

---

# #Level 0 ~ Level 4

### Level 0
SSH 프로토콜을 사용하여 워게임 시스템에 접속할 수 있다   
SSH는 Secure Shell의 약자로 네트워크 상의 신뢰하지 않는 시스템과 암호화된 통신을 할 수 있도록 해주는 프로토콜이다    

Linux 시스템에서 `ssh` 명령어로 동작하는 프로그램(`OpenSSH`)은 `SSH` 프로토콜을 사용하여 원격으로 로그인하고 명령어를 실행할 수 있도록 해준다
```shell
ssh {username}@{host}
ssh -p {port} {username}@{host}
```
`-p` 옵션을 사용하여 특정 포트로 접속할 수 있다

---

### Level 0 -> 1

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FbdOFyn%2FbtsMNANKhPN%2F45ckS4NOwx9RFeWmRNKK71%2Fimg.png)
```shell
cat readme
```
`ls` 명령어를 사용하여 현재 위치에서 디렉토리에 있는 항목 목록을 출력할 수 있다   
현재 위치는 `bandit`이라는 이름을 가진 사용자의 홈 디렉토리이다   
참고로, 현재 위치는 `pwd` 명령어를 통해서도 확인할 수 있다

각 사용자의 홈 디렉토리 이름은 사용자의 이름과 같다   
`bandit` 사용자로 로그인된 상태에서 `/` 경로는 이 위치가 된다   


`readme` 파일이 있는 것을 확인할 수 있는데 `cat` 명령어를 사용해 읽을 수 있다   
concatenate의 약자로 인자로 특정 파일 위치를 주면 해당 파일의 내용을 출력한다

---

### Level 1 -> 2

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FB0gg3%2FbtsMOjktRCN%2FA9gGQb9d3DyPHkbohc0Gh1%2Fimg.png)

파일명이 `-`(대쉬, Dash) 문자로 시작하는 경우 `cat -` 등의 명령어가 먹지 않는다   
대쉬는 명령어를 사용할 때 옵션 또는 인자로 사용되기 때문이다

`./`을 사용해서 파일 위치를 지정해주면 된다   
리눅스 시스템에서 파일 경로를 나타낼 때 `.`(온점)으로 시작하는 경우 기준점이 현재 디렉토리가 되고, `/`로 시작하면 홈 디렉토리가 기준이 된다   
상위 디렉토리는 `..`으로 나타낼 수 있다

```shell
cat ./-
cat < -
more -
rev - | rev
head ./-
```
이 외 파일 내용을 출력하는 명령어에서도 `./-` 를 사용해야 하며 `more`, `rev`의 경우는 예외이다.   

`more` 명령어는 긴 출력을 읽기 힘든 CLI 환경에서 사용되는 명령어로 긴 출력을 페이지로 나누어서 읽을 수 있도록 해준다   
`rev` 명령어는 인자로 받은 파일 또는 입력을 거꾸로 출력해준다

---

### Level 2 -> 3

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FrgTuq%2FbtsMNpMpLdA%2Fa8wEnVSnHFhf2hfbRFmbh1%2Fimg.png)

공백 문자가 포함된 파일명을 가진 파일 또는 폴더를 `cd` 또는 `cat` 등의 명령어의 인자로 주어야 할 때 이름을 따옴표(`' '`)로 감싸서 인자로 전달해주어야 한다

명령어에서 여러 인자를 받을 때 띄어쓰기를 기준으로 구분하여 받기 때문이다

---

### Level 3 -> 4

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FkYcwX%2FbtsMNxXSHgf%2F692a3l85dgu3QZm8VkB4j1%2Fimg.png)

숨겨진 파일은 `ls` 명령어로는 보이지 않는다   
리눅스에서는 파일명 앞에 `.`(온점)을 붙이면 숨김 처리된다

`ls` 명령어에 `-a` 옵션을 추가하거나 `ll` 명령어를 사용하면 숨긴 파일까지 볼 수 있다   
`cat` 명령어로 읽을 수 있다

---

### Level 4 -> 5

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FbaWM3Q%2FbtsMOSzYALh%2Fxk6nJIGz9SgZftZTnitXDK%2Fimg.png)

10개의 파일이 주어져있다   
문제 설명에서 `human-readable` 파일에 password가 있다고 하니 이중에서 찾아야 할 것 같다

파일명이 대쉬로 시작하니 Level 1 처럼 `cat ./-file00` 형식으로 명령어를 사용해야 한다

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FrheH0%2FbtsMMAOy662%2F0EHUXdkH2YP6b7EytpgH3K%2Fimg.png)

`file` 명령어로 파일의 형식을 확인할 수 있는데 `-file07` 파일 이외의 파일들은 `data` 형식이고 `-file07` 파일은 아스키 코드라 나온다   
`human-readable` 파일이니 `cat`으로 확인하면 password를 찾을 수 있다

---

## Level 5 ~ Level 7

### Level 5 -> 6

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FPOdj6%2FbtsMNNGeHUC%2FoLSRU40kVV5U1M71KBqSo1%2Fimg.png)

`human-readable`  
`1033 bytes in size`  
`not executable`

세 가지 조건을 만족하는 파일을 찾아서 읽어야 한다   
워낙 파일들 크기가 다양해서 그냥 1033 바이트 크기의 파일만 찾아서 걸러도 될 것 같다

```shell
du -ab ./* | grep 1033
```

`du` 명령어를 사용해서 모든 파일들의 크기를 확인할 수 있다    
disk usage 약자로 디스크 사용량에 대한 정보를 표시해주는 명령어다

`-a` 옵션으로 모든 파일 조회, `-b` 로 바이트 단위 사이즈 출력하고 `|` 파이프라인을 통해 `grep` 명령어로 1033 바이트 크기를 갖는 파일만 추려낸다   
`grep` 명령어는 정규식을 사용해서 탐색하는 명령어이다

정규식에 쓰이는 특수 문자 `*`은 모든 문자열를 나타내고 `?`은 모든 문자를 의미한다   
`./*`을 사용할 경우 모든 파일을 의미하며 하위 디렉토리까지 탐색한다

---

### Level 6 -> 7

`owned by user bandit7`  
`owned by group bandit6`  
`33 bytes in size`

리눅스 시스템은 동시에 여러 사용자가 작업할 수 있는 환경을 제공한다   
때문에 사용자와 그룹이 존재하는데 각각 디렉토리 또는 파일에 권한이 설정되어 있다   

소유자명이 `bandit7`, 소유그룹명이 `bandit6` 이고 33바이트 크기를 가지는 파일을 찾아 읽어내야 한다

![image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FckQm4i%2FbtsMObgC0TE%2F9cKjMNkcvwoIYXYaavkdR1%2Fimg.png)

```shell
find / -type f -size 33c -user bandit7 -group bandit6 2>/dev/null
```

`find` 명령어로 `/` 위치에서 탐색하며 조건에 맞는 파일을 찾을 수 있다

`-type f` 옵션으로 디렉터리가 아닌 파일만 조회한다   
`-user bandit7` 옵션으로 소유자명이 `badnit7`인 리소스를 조회한다     
`-group badnit6` 옵션으로 소유그룹명이 `bandit6`인 리소스를 조회한다   

`2>/dev/null` 로 Permission denied로 인해 발생하는 출력은 제외하여 깔끔하게 출력해준다

리눅스에서 프로세스는 입출력 스트림을 갖는데 0은 stdin 표준 입력, 1은 stdout 표준 출력이고 2는 stderr 표준 오류이다    
`/dev/null`은 휴지통 같은 곳이라 이곳에 데이터를 보내면 사라진다   
때문에 표준 오류를 `>` 로 리다이렉션하여 `Permission denied` 오류가 출력되지 않도록 하는 것이다   

---

### Level 7 -> 8

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FdcAprV%2FbtsMPNk2hQ5%2FO7zei0saOHiYZG9o1p1bdk%2Fimg.png)

그냥 `cat data.txt`를 하면 무수히 많은 단어가 출력되고 그 옆에 password 후보군들이 같이 출력된다   
문제 설명에서 말하듯 `millionth` 옆에 password가 있다고 하는데 `grep` 명령어로 찾아주면 된다

```shell
cat data.txt | grep millionth
```

---

## Level 8 ~ Level 13

### Level 8 -> 9

`data.txt`에 여러 줄의 password 후보군들이 출력되는데 그 중 딱 한번만 등장하는 라인이 password라고 한다

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FbJaxxj%2FbtsMPJJHXl3%2F8LcRvSZbLAbZJApCDaBKH1%2Fimg.png)

```shell
sort -d data.txt
```

`sort` 명령어로 정렬을 할 수 있는데 `-d` 옵션은 `dictionary` 사전순으로 내용을 정렬한다   
육안으로도 한번만 등장하는 문자열을 찾을 수 있긴 하다..

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FcSYV0s%2FbtsMOoz0U9e%2FWuLJBUahreXSXRwQkCagAk%2Fimg.png)

```shell
sort -d data.txt | uniq -u
```
`uniq` 명령어를 사용하면 조금 더 깔끔하게 찾을 수 있다    
`-u` 옵션을 사용하면 unique 한 것만 출력해준다는데 sort -d 를 해주지 않으면 제대로 안 나오는 걸 봐서 정렬된 값을 입력으로 주어야 하는 것 같다

---

### Level 9 -> 10

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2Fm9FLo%2FbtsMNGVw5N3%2FoUrt8IqWVH84tlh4bFF32k%2Fimg.png)

그냥 `cat`으로 `data.txt`를 읽으면 난장판이 난다   
마치 바이너리를 `cat`으로 읽은 듯한 느낌인데 이중에 `human-readable` 찾으면 그게 password라고 한다

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FnRyfO%2FbtsMOdyLXFm%2FnsmlVziRCoJ9VeaGHWPHGK%2Fimg.png)

```shell
strings data.txt
```

`strings` 명령어는 `printable characters`를 파일에서 찾아서 출력해준다

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FCbxem%2FbtsMOtuqP0K%2FR8tpppx6TDjqxDasYr7PL0%2Fimg.png)

```shell
strings data.txt | grep '====='
```

등호가 몇 개 있다는 힌트가 있기 때문에 `grep` 명령어로 조금 더 깔끔하게 출력해볼 수 있다   
`the password is ~` 라는 문장이 완성된다

---

### Level 10 -> 11

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FVsayJ%2FbtsMN9JTJ2r%2FBPMreQybZYhWqbO0kArrN1%2Fimg.png)

`base64`로 인코딩되어 있다고 한다   
`base64`는 양방향 해쉬의 일종이다

`base64` 명령어에 `-d` (decode) 옵션을 주면 `base64` 디코딩된 결과를 출력해준다

---

### Level 11 -> 12

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FbpHCwk%2FbtsMOCEOE5m%2FsyYDYhTk2BokDDQXP3vbd0%2Fimg.png)

password가 `ROT13` 카이사르 암호로 암호화되어 있다고 한다
`ROT13`은 알파벳을 13자리씩 밀어서 암호화한 것으로 역으로 13자리를 쉽게 복호화할 수 있다

`tr` 명령어를 사용하여 13번씩 알파벳을 밀 수 있다   
문자열을 변형하는 명령어인데 기본 활용형이 첫 번째 인자를 두 번째 인자로 번역한다   

---

### Level 12 -> 13

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FuCRlc%2FbtsMPwyeTnU%2FHy6RTl8r0TLLCXmbmQobM0%2Fimg.png)

문제 설명에서 반복되서 압축된 파일이 있다고 한다   
`cat`으로 `data.txt`를 읽으면 헥스 덤프 형태의 파일을 확인할 수 있다

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FdqkW7P%2FbtsMQCK1EGg%2Ff2TCixAIebRKMpGOd1XWkk%2Fimg.png)

홈 디렉토리에서는 파일 생성 권한이나 접근 권한이 없기 때문에 `mktemp -d` 또는 `/tmp` 디렉토리를 사용해볼 수 있다   
`mktemp` 명령어로 랜덤한 문자열의 이름을 갖는 임시 디렉토리를 `/tmp` 위치에 생성할 수 있다

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2Fc1HeKZ%2FbtsMQHFqrmV%2Fx0rHf38rzjS31BjAEI6Lk1%2Fimg.png)

`xxd` 명령어를 이용해서 헥스 덤프를 복호화했더니 알 수 없는 인코딩 값들이 나온다   
`xxd`는 헥스 덤프를 뜨거나 헥스 덤프를 복호화하는 명령어이다

`fdata2.bin` 문자열이 보이는 걸로 봐서는 `fdata2.bin`이라는 파일을 얻어야 할 것 같다

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FmQeHD%2FbtsMQ5MP5Mh%2FDXSMEwtXYNuL1iJnmKu47K%2Fimg.png)
![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FbwGqri%2FbtsMQDb6hqP%2FAUdcsfPabhjYS0Pkl1yEuK%2Fimg.png)

`xxd` 명령어로 헥스값을 뜯어보면 `1f 8b 08 08`이라는 값을 찾을 수 있는데 이는 `gzip` 파일의 파일 시그니처이다   
`file` 명령어를 통해서도 해당 파일이 `gzip`으로 압축되어 있다는 것을 알 수 있다

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FbjismQ%2FbtsMP9CrPTz%2FEOD4lzPhFL0OcYAn4XS3z1%2Fimg.png)

```shell
gzip -d data2.gz
```
`gzip` 명령어에 `-d` (decompress) 옵션을 주어 압축을 해제할 수 있다   
압축을 해제하고 보니 여전히 인코딩 값들이 나온다

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2Fcq36jC%2FbtsMRkiHfSi%2Fge6KxkzYK08MH5jJtYluu1%2Fimg.png)
![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FPNQ0h%2FbtsMQpZlLg9%2FxHbkQqn7NGYZ02q0hUNOWk%2Fimg.png)

`file` 명령어로 확인해보면 `bzip2`로 압축되어 있다고 나온다

```shell
bzip2 -d data2.bin
```
`bzip2` 명령어에 `-d` (decompress) 옵션을 주어 압축을 해제할 수 있다    
새로운 파일을 얻었는데 또 `gzip`으로 압축되어 있다

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FbcMdCA%2FbtsMO6fLf7C%2Fi10qIRT8IAuUTIiIWwddhK%2Fimg.png)

같은 방식으로 진행하다 보면 `POSIX tar archive`라고 나오는데 이는 `tar` 확장자로 압축되었다는 뜻이다

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FNrp8Z%2FbtsMOXDgvF3%2FtYFlzEzh0C7TNATrJWKCA1%2Fimg.png)

```shell
tar xsf data.tar
```

`tar` 명령어에서 `xsf` 옵션을 사용하였는데 `x` 옵션은 파일들을 추출, `s` 옵션은 압축된 파일 명시, `f` 옵션은 압축 파일명을 다음 인자로 보내겠다는 의미이다   
따라서 해당 명령어는 `data.tar` 압축 파일에서 모든 파일들을 추출하는 명령어이다

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FoEzr2%2FbtsMQEaRHDE%2F9hg406Tu2DPdecDrbErK51%2Fimg.png)
![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2Fcj4jqx%2FbtsMPkdQmOa%2FrDGt0bxxOag9oc97qREC9K%2Fimg.png)

tar를 압축 해제하여 얻은 `data6.bin` 파일은 `bzip2` 압축 파일이었고 이 파일까지 압축을 해제하면 password를 얻을 수 있다

---

### Level 13 -> 14

```shell
ssh -i ./sshkey.private -p 2220 bandit14@localhost
```

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FdAsBYc%2FbtsMRcTid8E%2FHe3nfNUtBxJXAb8oV92d3k%2Fimg.png)

`sshkey.private` 파일이 주어지는데 이를 이용해서 `ssh`에 접근할 수 있다

<!--

---

## Level 14 ~ Level 17

### Level 14 -> 15

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FbvHgxE%2FbtsMPxxPo8D%2F6SFRg3TNFyAwm5ox119Z51%2Fimg.png)

netcat 명령어를 이용해서 30000포트에 이전 password를 보내면 응답으로 다음 Level의 password를 얻을 수 있다

---

### Level 15 -> 16

![Image](https://img1.daumcdn.net/thumb/R1280x0/?scode=mtistory2&fname=https%3A%2F%2Fblog.kakaocdn.net%2Fdn%2FbCfJjC%2FbtsMRewQncw%2FSPxKb3oMU0KHJaRNVVY2m0%2Fimg.png)

```shell
openssl s_client -connect localhost:30001
```

30001 포트와 SSL/TLS 암호화를 사용하여 통신할 수 있다
-->

<!--
bundle exec jekyll serve --livereload 
-->