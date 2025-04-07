# CAUtion Blog

이곳은 CAUtion 멤버들이 자유롭게 포스팅할 수 있는 Github 블로그 Repository 입니다😊

[[🔗Blog URL] cau-tion.github.io](https://cau-tion.github.io)

<br>

아래의 가이드를 참고하여 포스팅 해보세요

<br>

## #Step1: Fork Repository

<img src="https://github.com/user-attachments/assets/dd77a8d7-8f42-4c64-bf0b-73d4b1ea4d90" style="width:500px;border:2px solid black">

본인의 계정으로 github 로그인 후 레포지토리 fork!

<br>

## #Step2: Add author

**1) 프로필 정보 등록**

<img src="https://github.com/user-attachments/assets/168c89da-0de6-497c-9f07-0a2cafaf7437" style="width:300px;border:2px solid black">

`/_data/autors.yml` 파일에 본인의 프로필 정보 등록

<br>

**2) 프로필 이미지 등록**

`/assets/img/avatar/{Nickname 제목의 이미지 파일}`

위의 경로에 등록하고자 하는 이미지 파일 추가

<br>

## #Step3: Write Post

**1) md 파일 생성**

`/_posts/{post.md}`

위의 경로에 md 파일 생성. 파일명은 `YYYY-MM-DD-title.md`로 설정.

<br>

**2) Front matter 추가**

```markdown
---
title: "제목"
excerpt: "설명"
author: Nickname # 위에서 등록한 author nickname

categories: # 카테고리 설정
    - categories1
tags: # 포스트 태그
    - [tag1, tag2]

date: 2020-05-21 # 작성 날짜
last_modified_at: 2021-10-09 # 최종 수정 날짜
---
```

위의 front matter를 md 파일 첫 줄에 추가.

<br>

**3) 본문 작성**

front matter 아래부터 블로그 본문 작성. markdown 및 kramdown 형식을 사용하여 작성.

<br>

> ### 💡 **이미지 첨부 방식**
>
> 1. `/_posts/img/{Nickname-post_title}` 위치에 파일명 준수하여 이미지 저장 후 참조하여 사용
> 2. [Markdown에서 이미지 첨부 using Github issue](https://cau-tion.github.io/etc/Insert-image-in-markdown/)

<br>

## #Step4: Pull Request

**1) 파일 저장 후 Commit & Push**

Step2, Step3에서 만든 파일을 모두 저장하고 commit 및 원격 브랜치에 push

<br>

**2) Open pull request**

<img src="https://github.com/user-attachments/assets/003b12e6-1979-45c7-badc-f3d5d152af54" style="width:500px;border:2px solid black">

본인 레포지토리에 push 된 파일 확인 후에 **_Contribute > Open pull request_** 클릭

<br>

**3) Create pull request**

<img src="https://github.com/user-attachments/assets/f15d8b65-2650-49e6-ba2d-6fa0b4cc3df9" style="width:500px;border:2px solid black">

-   **base repository:** CAU-tion/CAU-tion.github.io | **base:** master
-   **head repository:** {본인 github id}/CAU-tion.github.io | **compare:** master

레포지토리 설정 후 하단의 **_Crate pull request_** 클릭

<br>

**4) View pull request**

<img src="https://github.com/user-attachments/assets/1b4000f8-a823-404f-86d4-058863de1e49" style="width:500px;border:2px solid black">

위의 이미지와 같이 **_Able to merge_** 및 **_View pull request_** 버튼이 존재하면 성공적으로 PR 완료.

<br>

## #Step5: Text to admin

운영진에게 본인의 깃허브 아이디와 함께 PR 전송 사실을 알리면 운영진이 확인 후 Merge 진행.
