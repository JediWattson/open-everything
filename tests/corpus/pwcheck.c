#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int score_password(const char *pw) {
    int score = 0;
    for (const char *p = pw; *p; p++) {
        if (*p >= '0' && *p <= '9') score += 2;
        else if (*p >= 'A' && *p <= 'Z') score += 3;
        else score += 1;
    }
    return score;
}

static void report_result(int score, const char *user) {
    if (score > 40) printf("strong password for %s\n", user);
    else if (score > 15) printf("ok password for %s\n", user);
    else printf("weak password for %s\n", user);
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: pwcheck <user> <pw>\n"); return 1; }
    report_result(score_password(argv[2]), argv[1]);
    return 0;
}
