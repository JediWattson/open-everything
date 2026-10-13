/* Varied control-flow shapes for fingerprint eval: loops, switches,
 * recursion, state machines, early exits, nested branches. */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

static int cmp_int(const void *a, const void *b) {
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

static unsigned fib_iter(unsigned n) {
    unsigned a = 0, b = 1;
    while (n--) { unsigned t = a + b; a = b; b = t; }
    return a;
}

static unsigned fib_rec(unsigned n) {
    return n < 2 ? n : fib_rec(n - 1) + fib_rec(n - 2);
}

static long sum_evens(const int *v, long n) {
    long s = 0;
    for (long i = 0; i < n; i++)
        if (!(v[i] & 1)) s += v[i];
    return s;
}

static int count_words(const char *s) {
    int n = 0, in = 0;
    for (; *s; s++) {
        if (isspace((unsigned char)*s)) { in = 0; continue; }
        if (!in) { in = 1; n++; }
    }
    return n;
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static long parse_num(const char *s, int base) {
    long v = 0;
    int d;
    while ((d = hexval(*s)) >= 0 && d < base) {
        v = v * base + d;
        s++;
    }
    return v;
}

static const char *http_status(int code) {
    switch (code) {
    case 200: return "OK";
    case 301: return "Moved";
    case 302: return "Found";
    case 400: return "Bad";
    case 401: return "Auth";
    case 403: return "Denied";
    case 404: return "Missing";
    case 500: return "Oops";
    default:  return "?";
    }
}

static int level_of(int score) {
    switch (score / 10) {
    case 10:
    case 9:  return 5;
    case 8:  return 4;
    case 7:  return 3;
    case 6:  return 2;
    default: return score > 0 ? 1 : 0;
    }
}

static char *dup_range(const char *s, long a, long b) {
    if (a < 0 || b <= a) return NULL;
    char *p = malloc(b - a + 1);
    if (!p) return NULL;
    memcpy(p, s + a, b - a);
    p[b - a] = 0;
    return p;
}

static int balanced(const char *s) {
    int d = 0;
    for (; *s; s++) {
        if (*s == '(') d++;
        else if (*s == ')' && --d < 0) return 0;
    }
    return d == 0;
}

static int st_run(const char *s) {
    /* tiny state machine: strip comments like a C lexer */
    int st = 0; /* 0 code, 1 slash, 2 line-comment, 3 block, 4 star */
    int kept = 0;
    for (; *s; s++) {
        switch (st) {
        case 0:
            if (*s == '/') st = 1; else kept++;
            break;
        case 1:
            if (*s == '/') st = 2;
            else if (*s == '*') st = 3;
            else { st = 0; kept += 2; }
            break;
        case 2:
            if (*s == '\n') st = 0;
            break;
        case 3:
            if (*s == '*') st = 4;
            break;
        case 4:
            st = (*s == '/') ? 0 : (*s == '*' ? 4 : 3);
            break;
        }
    }
    return kept;
}

static long gcd_rec(long a, long b) {
    return b ? gcd_rec(b, a % b) : a;
}

static int is_prime(unsigned n) {
    if (n < 2) return 0;
    if (n < 4) return 1;
    if (!(n & 1)) return 0;
    for (unsigned i = 3; i * i <= n; i += 2)
        if (!(n % i)) return 0;
    return 1;
}

static void heap_sift(int *h, long i, long n) {
    for (;;) {
        long l = 2 * i + 1, r = l + 1, m = i;
        if (l < n && h[l] > h[m]) m = l;
        if (r < n && h[r] > h[m]) m = r;
        if (m == i) return;
        int t = h[i]; h[i] = h[m]; h[m] = t;
        i = m;
    }
}

int main(int argc, char **argv) {
    int vals[64];
    long n = 0;
    for (int i = 1; i < argc && n < 64; i++)
        vals[n++] = (int)parse_num(argv[i], 16);
    qsort(vals, n, sizeof *vals, cmp_int);
    for (long i = 0; i < n; i++)
        printf("%d %ld\n", vals[i], (long)fib_iter((unsigned)vals[i]));
    printf("words=%d prime=%d bal=%d kept=%d lvl=%d st=%s\n",
           count_words("a b  c"), is_prime(97), balanced("(()())"),
           st_run("a/*x*/b//c"), level_of(85), http_status(404));
    printf("fib=%u gcd=%ld sum=%ld dup=%s\n", fib_rec(10),
           gcd_rec(24, 18), sum_evens(vals, n),
           dup_range("hello", 1, 4) ?: "null");
    return 0;
}
