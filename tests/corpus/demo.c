#include <string.h>
#include <stdio.h>

static int split_pair(char *line, char **key, char **val) {
    char *eq = strchr(line, '=');
    if (!eq) return -1;
    *eq = '\0';
    *key = line;
    *val = eq + 1;
    return 0;
}

static unsigned rotl(unsigned x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void xor_crypt(char *data, long len, unsigned key) {
    for (long i = 0; i < len; i++)
        data[i] ^= (key = rotl(key ^ 0x9e3779b9, 5));
}

int main(int argc, char **argv) {
    char line[256];
    while (fgets(line, sizeof line, stdin)) {
        char *k, *v;
        if (split_pair(line, &k, &v) == 0) {
            xor_crypt(v, strlen(v) - 1, 0xdead);
            printf("%s=%s", k, v);
        }
    }
    return 0;
}
