// spliced: ls + vault slice ['_xor_crypt', '_parse_config', '_fetch_remote_secret', '_checksum']
#include "decls.h"

// ===== ls =====
// FUN_100000718 (ls)
void compare_strings(long param_1, long param_2) {
  _strcoll((char *)(param_1 + 0x68), (char *)(param_2 + 0x68));
  return;
}

// FUN_10000072a (ls)
void compare_strings_2(long param_1, long param_2) {
  _strcoll((char *)(param_2 + 0x68), (char *)(param_1 + 0x68));
  return;
}

// FUN_10000073f (ls)
int compare_objects(long obj1, long obj2) {
  long prop1 = *(long *)(*(long *)(obj1 + 0x60) + 0x30);
  int result = 1;
  long prop2 = *(long *)(*(long *)(obj2 + 0x60) + 0x30);
  if (prop1 <= prop2) {
    if (prop1 < prop2) {
      result = -1;
    } else {
      prop1 = *(long *)(*(long *)(obj1 + 0x60) + 0x38);
      prop2 = *(long *)(*(long *)(obj2 + 0x60) + 0x38);
      if ((prop2 <= prop1) && (result = -1, prop1 <= prop2)) {
        long temp = obj1;
        if (DAT_100005584 == 0) {
          temp = obj2;
          obj2 = obj1;
        }
        result = _strcoll((char *)(obj2 + 0x68), (char *)(temp + 0x68));
        return result;
      }
    }
  }
  return result;
}

// FUN_10000079f (ls)
void fun_10000079f(void) {
  compare_objects(param_2, param_1);
  return;
}

// FUN_1000007b2 (ls)
int compare_records(long record1, long record2) {
  long value1 = *(long *)(*(long *)(record1 + 0x60) + 0x20);
  int result = 1;
  long value2 = *(long *)(*(long *)(record2 + 0x60) + 0x20);
  if (value1 <= value2) {
    if (value1 < value2) {
      result = -1;
    } else {
      long string1 = *(long *)(*(long *)(record1 + 0x60) + 0x28);
      long string2 = *(long *)(*(long *)(record2 + 0x60) + 0x28);
      if ((string1 <= string2) && (result = -1, string1 <= string2)) {
        long recordToCompare = record1;
        if (DAT_100005584 == 0) {
          recordToCompare = record2;
          record2 = record1;
        }
        result = _strcoll((char *)(record2 + 0x68), (char *)(recordToCompare + 0x68));
        return result;
      }
    }
  }
  return result;
}

// FUN_100000812 (ls)
void fun_100000812(void) {
  compare_records(param_2, param_1);
  return;
}

// FUN_100000825 (ls)
int compare_records_2(long record1, long record2) {
  long value1 = *(long *)(*(long *)(record1 + 0x60) + 0x50);
  int result = 1;
  long value2 = *(long *)(*(long *)(record2 + 0x60) + 0x50);
  if (value1 <= value2) {
    if (value1 < value2) {
      result = -1;
    } else {
      long string1 = *(long *)(*(long *)(record1 + 0x60) + 0x58);
      long string2 = *(long *)(*(long *)(record2 + 0x60) + 0x58);
      if ((string1 <= string2) && (result = -1, string1 <= string2)) {
        long recordToCompare = record1;
        if (DAT_100005584 == 0) {
          recordToCompare = record2;
          record2 = record1;
        }
        result = _strcoll((char *)(record2 + 0x68), (char *)(recordToCompare + 0x68));
        return result;
      }
    }
  }
  return result;
}

// FUN_100000885 (ls)
void fun_100000885(long record1, long record2) {
  compare_records_2(record2, record1);
  return;
}

// FUN_100000898 (ls)
int compare_records_3(long record1, long record2) {
  long value1 = *(long *)(*(long *)(record1 + 0x60) + 0x40);
  int result = 1;
  long value2 = *(long *)(*(long *)(record2 + 0x60) + 0x40);
  if (value2 <= value1) {
    if (value2 < value1) {
      result = -1;
    } else {
      long string1 = *(long *)(*(long *)(record1 + 0x60) + 0x48);
      long string2 = *(long *)(*(long *)(record2 + 0x60) + 0x48);
      if ((string2 <= string1) && (result = -1, string1 <= string2)) {
        long recordToCompare = record1;
        if (DAT_100005584 == 0) {
          recordToCompare = record2;
          record2 = record1;
        }
        result = _strcoll((char *)(record2 + 0x68), (char *)(recordToCompare + 0x68));
        return result;
      }
    }
  }
  return result;
}

// FUN_1000008f8 (ls)
void fun_1000008f8(long record1, long record2) {
  compare_records_3(record2, record1);
  return;
}

// FUN_10000090b (ls)
int compare_items(long item1, long item2) {
  long addr1 = *(long *)(*(long *)(item1 + 0x60) + 0x60);
  long addr2 = *(long *)(*(long *)(item2 + 0x60) + 0x60);
  int result = 1;
  if ((addr2 <= addr1) && (result = -1, addr1 <= addr2)) {
    result = _strcoll((char *)(item1 + 0x68), (char *)(item2 + 0x68));
  }
  return result;
}

// FUN_10000093d (ls)
int compare_items_2(long item1, long item2) {
  long value1 = *(long *)(*(long *)(item2 + 0x60) + 0x60);
  long value2 = *(long *)(*(long *)(item1 + 0x60) + 0x60);
  int result = 1;
  if ((value2 <= value1) && (result = -1, value1 <= value2)) {
    result = _strcoll((char *)(item2 + 0x68), (char *)(item1 + 0x68));
  }
  return result;
}

// FUN_1000041eb (ls)
void print_usage_and_exit(void) {
  _fprintf(*(FILE **)PTR____stderrp_100005550, "usage: ls [-@ABCFGHILOPRSTUWXabcdefghiklmnopqrstuvwxy1%%,] [--color=when] [-D format] [file ...]\n");
  _exit(1);
}

// FUN_1000036b6 (ls)
void FUN_1000036b6(char *param_1)

{
  byte bVar1;
  bool bVar2;
  bool bVar3;
  __darwin_ct_rune_t _Var4;
  char *pcVar5;
  size_t sVar6;
  char *pcVar7;
  long lVar8;
  bool bVar9;
  byte bVar10;
  long lVar11;
  
  pcVar5 = "";
  if (param_1 != (char *)0x0) {
    pcVar5 = param_1;
  }
  sVar6 = _strlen(pcVar5);
  lVar8 = 0;
  bVar2 = false;
  do {
    (&DAT_100005698)[lVar8 * 3] = 0;
    pcVar7 = "exfxcxdxbxegedabagacadah";
    if ((ulong)(lVar8 * 2) < sVar6) {
      pcVar7 = pcVar5;
    }
    bVar1 = pcVar7[lVar8 * 2 + 1];
    lVar11 = 0;
    bVar10 = pcVar7[lVar8 * 2];
    bVar3 = true;
    do {
      bVar9 = bVar3;
      if ((bVar10 & 0xf8) == 0x30) {
        (&DAT_100005690)[lVar8 * 3 + lVar11] = (uint)(byte)(bVar10 - 0x30);
        if (!bVar2) {
          _warnx("LSCOLORS should use characters a-h instead of 0-9 (see the manual page)");
        }
        bVar2 = true;
      }
      else if ((byte)(bVar10 + 0x9f) < 8) {
        (&DAT_100005690)[lVar8 * 3 + lVar11] = (uint)(byte)(bVar10 + 0x9f);
      }
      else if ((byte)(bVar10 + 0xbf) < 8) {
        (&DAT_100005690)[lVar8 * 3 + lVar11] = (uint)(byte)(bVar10 + 0xbf);
        (&DAT_100005698)[lVar8 * 3] = 1;
      }
      else {
        _Var4 = ___tolower((uint)bVar10);
        if (_Var4 != 0x78) {
          _warnx("invalid character \'%c\' in LSCOLORS env var",(int)(char)bVar10);
        }
        (&DAT_100005690)[lVar8 * 3 + lVar11] = 0xffffffff;
      }
      lVar11 = 1;
      bVar10 = bVar1;
      bVar3 = false;
    } while (bVar9);
    lVar8 = lVar8 + 1;
  } while (lVar8 != 0xc);
  return;
}

// FUN_1000040e7 (ls)
void fts_open_error(void) {
    _err(1, "fts_open");
}

// FUN_1000040d2 (ls)
void fts_read_error(void) {
    _err(1, "fts_read");
}

// FUN_100004179 (ls)
void user_from_uid_error(void) {
    _err(1, "user_from_uid");
}

// FUN_100004164 (ls)
void group_from_gid_error(void) {
    _err(1, "group_from_gid");
}

// FUN_10000414f (ls)
void handle_malloc_failure(void) {
    _err(1, "malloc");
}

// FUN_10000413a (ls)
void fflagstostr(void) {
    _err(1, "fflagstostr");
}

// FUN_1000040fc (ls)
void handle_error(long error_code) {
  char *error_message;

  error_message = _strerror(*(int *)(error_code + 0x38));
  _warnx("%s: %s", error_code + 0x68, error_message);
  *(undefined8 *)(error_code + 0x18) = 1;
  DAT_100005678 = 1;
  return;
}

// FUN_100003caa (ls)
long FUN_100003caa(char *param_1,int param_2)

{
  uint uVar1;
  size_t sVar2;
  long lVar3;
  long lVar4;
  size_t sVar5;
  wchar_t local_bc;
  mbstate_t local_b8;
  long local_38;
  
  local_38 = *(long *)PTR____stack_chk_guard_100005548;
  local_b8._mbstateL = 0;
  local_b8._8_8_ = 0;
  local_b8._16_8_ = 0;
  local_b8._24_8_ = 0;
  local_b8._32_8_ = 0;
  local_b8._40_8_ = 0;
  local_b8._48_8_ = 0;
  local_b8._56_8_ = 0;
  local_b8._64_8_ = 0;
  local_b8._72_8_ = 0;
  local_b8._80_8_ = 0;
  local_b8._88_8_ = 0;
  local_b8._96_8_ = 0;
  local_b8._104_8_ = 0;
  local_b8._112_8_ = 0;
  local_b8._120_8_ = 0;
  if (param_2 == 0) {
    lVar4 = 0;
  }
  else {
    sVar5 = (size_t)param_2;
    lVar4 = 0;
    do {
      while( true ) {
        sVar2 = _mbrtowc(&local_bc,param_1,sVar5,&local_b8);
        if (sVar2 == 0xfffffffffffffffe) {
          lVar4 = lVar4 + ((int)sVar5 << 2);
          goto LAB_100003dd1;
        }
        if (sVar2 == 0) goto LAB_100003dd1;
        if (sVar2 == 0xffffffffffffffff) break;
        if ((ulong)(uint)local_bc < 0x80) {
          uVar1 = *(uint *)(PTR___DefaultRuneLocale_100005540 + (ulong)(uint)local_bc * 4 + 0x3c) &
                  0x40000;
        }
        else {
          uVar1 = ___maskrune(local_bc,0x40000);
        }
        lVar3 = sVar2 * 4;
        if (uVar1 != 0) {
          lVar3 = 1;
        }
        lVar4 = lVar4 + lVar3;
        param_1 = param_1 + sVar2;
      }
      lVar4 = lVar4 + 4;
      param_1 = param_1 + 1;
      local_b8._112_8_ = 0;
      local_b8._120_8_ = 0;
      local_b8._96_8_ = 0;
      local_b8._104_8_ = 0;
      local_b8._80_8_ = 0;
      local_b8._88_8_ = 0;
      local_b8._64_8_ = 0;
      local_b8._72_8_ = 0;
      local_b8._48_8_ = 0;
      local_b8._56_8_ = 0;
      local_b8._32_8_ = 0;
      local_b8._40_8_ = 0;
      local_b8._16_8_ = 0;
      local_b8._24_8_ = 0;
      local_b8._mbstateL = 0;
      local_b8._8_8_ = 0;
      sVar5 = sVar5 - 1;
    } while (sVar5 != 0);
  }
LAB_100003dd1:
  if (*(long *)PTR____stack_chk_guard_100005548 != local_38) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail();
  }
  return lVar4;
}

// FUN_100001977 (ls)
void parse_ls_colwidths(long param_1, long param_2) {
    char *env_colwidths = getenv("LS_COLWIDTHS");
    if (env_colwidths == NULL) {
        return;
    }

    char *token = strtok(env_colwidths, ":");
    unsigned long colwidths[10] = {0};
    int index = 0;

    while (token != NULL && index < 10) {
        colwidths[index] = strtoul(token, NULL, 10);
        token = strtok(NULL, ":");
        index++;
    }

    unsigned long total_width = 0;
    for (int i = 0; i < index; i++) {
        total_width += colwidths[i];
    }

    // Process file attributes here
    // ...
}

// FUN_100001620 (ls)
void parse_ls_colwidths_2(long param_1, long param_2) {
    // Function body remains unchanged
}

// entry (ls)
/* WARNING: Type propagation algorithm not settling */

void entry(int param_1,long param_2)

{
  FILE *pFVar1;
  uint uVar2;
  bool bVar3;
  byte bVar4;
  BOOL BVar5;
  int iVar6;
  uid_t uVar7;
  int iVar8;
  uint uVar9;
  char *pcVar10;
  long lVar11;
  byte bVar12;
  undefined **ppuVar13;
  bool bVar14;
  char local_668 [1024];
  char local_268 [520];
  undefined1 local_60 [2];
  ushort local_5e;
  int local_58 [2];
  char *local_50;
  long local_48;
  char *pcStack_40;
  uint local_34;
  
  local_48 = 0;
  local_50 = local_268;
  if (param_1 < 1) {
    print_usage_and_exit();
  }
  _setlocale(0,"");
  BVar5 = _compat_mode("bin/ls","Unix2003");
  DAT_10000557c = (char)BVar5;
  iVar6 = _isatty(1);
  if (iVar6 == 0) {
    DAT_100005630 = '\x01';
    pcVar10 = _getenv("COLUMNS");
    if (pcVar10 != (char *)0x0) {
      DAT_100005510 = _strtonum(pcVar10,0,0x7fffffff,&local_48);
    }
  }
  else {
    DAT_100005510 = 0x50;
    pcVar10 = _getenv("COLUMNS");
    if ((pcVar10 == (char *)0x0) || (*pcVar10 == '\0')) {
      iVar6 = _ioctl(1,0x40087468,local_60);
      if (local_5e != 0 && iVar6 != -1) {
        DAT_100005510 = (uint)local_5e;
      }
    }
    else {
      DAT_100005510 = _strtonum(pcVar10,0,0x7fffffff,&local_48);
    }
    DAT_100005580 = 1;
  }
  if (local_48 != 0) {
    DAT_100005510 = 0x50;
  }
  pcVar10 = _getenv("LS_SAMESORT");
  if (pcVar10 != (char *)0x0) {
    DAT_100005584 = 1;
  }
  pcVar10 = _getenv("CLICOLOR");
  if (pcVar10 != (char *)0x0) {
    DAT_100005578 = 1;
  }
  local_34 = 0x10;
LAB_100000af4:
  do {
    iVar6 = _getopt_long(param_1,param_2,"+@1ABCD:FGHILOPRSTUWXabcdefghiklmnopqrstuvwxy%,",
                         &PTR_s_color_1000052a0,0);
    switch(iVar6) {
    case 0x25:
      DAT_1000055e0 = 1;
      break;
    case 0x2c:
      DAT_10000559c = 1;
      break;
    case 0x31:
      DAT_100005630 = '\x01';
      DAT_100005588 = 0;
      DAT_100005634 = '\0';
      break;
    case 0x40:
      DAT_1000055dc = 1;
      break;
    case 0x41:
      goto code_r0x000100000f8b;
    case 0x42:
      DAT_100005580 = 0;
      DAT_1000055a0 = 1;
      DAT_1000055a4 = 0;
      break;
    case 0x43:
      DAT_100005630 = '\0';
      DAT_100005588 = 0;
      DAT_10000558c = 0;
      break;
    case 0x44:
      DAT_1000055a8 = *(undefined8 *)PTR__optarg_100005560;
      break;
    case 0x46:
      DAT_1000055b0 = 1;
      DAT_1000055b4 = 0;
      break;
    case 0x47:
      _setenv("CLICOLOR","",1);
code_r0x000100000ebe:
      DAT_100005578 = 1;
      break;
    case 0x48:
      uVar9 = local_34 & 0xfffffbed;
      local_34 = local_34 | 1;
      if (DAT_10000557c != '\0') {
        local_34 = uVar9 | 0x410;
      }
      DAT_100005648 = '\0';
      break;
    case 0x49:
      DAT_10000564c = 1;
      break;
    case 0x4c:
      DAT_100005648 = '\0';
      uVar9 = local_34 & 0xffffffed;
      if (DAT_10000557c != '\0') {
        uVar9 = local_34 & 0xfffffbec;
      }
      local_34 = uVar9 | 2;
      break;
    case 0x50:
      local_34 = local_34 & 0xfffffbec | 0x10;
      DAT_100005648 = '\x01';
      break;
    case 0x52:
      DAT_100005650 = 1;
      break;
    case 0x53:
      DAT_100005640 = 1;
      DAT_100005644 = 0;
      break;
    case 0x54:
      DAT_1000055b8 = 1;
      break;
    case 0x55:
      DAT_100005598 = 1;
      DAT_100005594 = 0;
      DAT_100005590 = 0;
      break;
    case 0x57:
      DAT_100005654 = '\x01';
      break;
    case 0x58:
      local_34 = local_34 | 0x40;
      break;
    case 0x62:
      DAT_100005580 = 0;
      DAT_1000055a0 = 0;
      DAT_1000055a4 = 1;
      break;
    case 99:
      DAT_100005590 = 1;
      DAT_100005594 = 0;
      DAT_100005598 = 0;
      break;
    case 100:
      DAT_100005658 = 1;
      DAT_100005650 = 0;
      break;
    case 0x65:
      DAT_1000055d8 = 1;
      break;
    case 0x66:
      DAT_100005638 = 1;
    case 0x61:
      local_34 = local_34 | 0x20;
      goto code_r0x000100000f8b;
    case 0x67:
      if (DAT_10000557c == '\x01') {
        DAT_1000055bc = 1;
        goto code_r0x000100000f6d;
      }
      break;
    case 0x68:
      DAT_1000055c0 = 1;
      break;
    case 0x69:
      DAT_1000055c4 = 1;
      break;
    case 0x6b:
      DAT_1000055c0 = 0;
      DAT_10000565c = '\x01';
      break;
    case 0x6c:
      goto code_r0x000100000c0d;
    case 0x6d:
      DAT_100005634 = '\x01';
      DAT_100005630 = '\0';
      DAT_100005588 = 0;
      break;
    case 0x6e:
      DAT_1000055c8 = 1;
      if (DAT_10000557c == '\x01') {
code_r0x000100000c0d:
code_r0x000100000f6d:
        DAT_100005588 = 1;
        DAT_100005630 = '\0';
        DAT_100005634 = '\0';
      }
      break;
    case 0x6f:
      if (DAT_10000557c == '\x01') {
        DAT_1000055cc = 1;
        goto code_r0x000100000f6d;
      }
    case 0x4f:
      DAT_1000055d0 = 1;
      break;
    case 0x70:
      DAT_1000055b4 = 1;
      DAT_1000055b0 = 1;
      break;
    case 0x71:
      DAT_100005580 = 1;
      goto code_r0x000100000f35;
    case 0x72:
      DAT_100005660 = '\x01';
      break;
    case 0x73:
      DAT_1000055d4 = 1;
      break;
    case 0x74:
      DAT_100005644 = 1;
      DAT_100005640 = 0;
      break;
    case 0x75:
      DAT_100005594 = 1;
      DAT_100005590 = 0;
      DAT_100005598 = 0;
      break;
    case 0x76:
      DAT_100005580 = 0;
      break;
    case 0x77:
      DAT_100005580 = 0;
code_r0x000100000f35:
      DAT_1000055a0 = 0;
      DAT_1000055a4 = 0;
      break;
    case 0x78:
      DAT_10000558c = 1;
      DAT_100005588 = 0;
      DAT_100005630 = '\0';
      break;
    case 0x79:
      DAT_100005584 = 1;
      break;
    case 0x80:
      pcStack_40 = *(char **)PTR__optarg_100005560;
      if ((((pcStack_40 == (char *)0x0) || (iVar6 = _strcmp(pcStack_40,"always"), iVar6 == 0)) ||
          (iVar6 = _strcmp(pcStack_40,"yes"), iVar6 == 0)) ||
         (iVar6 = _strcmp(pcStack_40,"force"), iVar6 == 0)) {
        DAT_100005578 = 2;
      }
      else {
        iVar6 = _strcmp(pcStack_40,"auto");
        if (((iVar6 == 0) || (iVar6 = _strcmp(pcStack_40,"tty"), iVar6 == 0)) ||
           (iVar6 = _strcmp(pcStack_40,"if-tty"), iVar6 == 0)) goto code_r0x000100000ebe;
        iVar6 = _strcmp(pcStack_40,"never");
        if ((iVar6 != 0) &&
           ((((*pcStack_40 != 'n' || (pcStack_40[1] != 'o')) || (pcStack_40[2] != '\0')) &&
            (iVar6 = _strcmp(pcStack_40,"none"), iVar6 != 0)))) {
                    /* WARNING: Subroutine does not return */
          _errx(2,"unsupported --color value \'%s\' (must be always, auto, or never)",pcStack_40);
        }
        DAT_100005578 = 0;
      }
      break;
    default:
      if (iVar6 == -1) {
        iVar6 = *(int *)PTR__optind_100005568;
        if (((DAT_10000563c == '\0') && (uVar7 = _getuid(), uVar7 == 0)) &&
           ((DAT_10000564c & 1) == 0)) {
          DAT_10000563c = '\x01';
        }
        if ((DAT_100005578 == 0) ||
           ((DAT_100005578 != 2 &&
            (((pcVar10 = _getenv("CLICOLOR"), pcVar10 == (char *)0x0 &&
              ((pcVar10 = _getenv("COLORTERM"), pcVar10 == (char *)0x0 || (*pcVar10 == '\0')))) ||
             ((iVar8 = _isatty(1), iVar8 == 0 &&
              (pcVar10 = _getenv("CLICOLOR_FORCE"), pcVar10 == (char *)0x0)))))))) {
LAB_100001183:
          if (DAT_100005610 != 0) goto LAB_100001190;
          bVar14 = false;
        }
        else {
          pcVar10 = _getenv("TERM");
          if ((pcVar10 == (char *)0x0) || (iVar8 = _tgetent(local_668,pcVar10), iVar8 != 1)) {
            if (DAT_100005578 != 2) goto LAB_100001183;
            DAT_100005610 = 1;
            DAT_100005614 = 1;
          }
          else {
            DAT_1000055e8 = _tgetstr("AF",&local_50);
            DAT_1000055f0 = _tgetstr("AB",&local_50);
            DAT_1000055f8 = _tgetstr("me",&local_50);
            DAT_100005600 = _tgetstr("md",&local_50);
            DAT_100005608 = _tgetstr("op",&local_50);
            bVar14 = true;
            if (DAT_100005608 == (char *)0x0) {
              DAT_100005608 = _tgetstr("oc",&local_50);
              bVar14 = DAT_100005608 != (char *)0x0;
            }
            if (!(bool)((DAT_1000055f0 != (char *)0x0 && DAT_1000055e8 != (char *)0x0) & bVar14))
            goto LAB_100001183;
            DAT_100005610 = 1;
          }
LAB_100001190:
          DAT_100005618 = 1;
          _signal(2);
          _signal(3);
          pcVar10 = _getenv("LSCOLORS");
          FUN_1000036b6(pcVar10);
          bVar14 = DAT_100005610 != 0;
        }
        uVar9 = local_34 | 8;
        if (bVar14) {
          uVar9 = local_34;
        }
        if (DAT_1000055e0 != 0 || DAT_1000055b0 != 0) {
          uVar9 = local_34;
        }
        if ((DAT_100005640 & 1) != 0) {
          uVar9 = local_34;
        }
        if ((DAT_100005644 & 1) != 0) {
          uVar9 = local_34;
        }
        bVar3 = DAT_1000055c4 != 0 || DAT_100005588 != 0;
        if (bVar3 || DAT_1000055d4 != 0) {
          uVar9 = local_34;
        }
        if (((DAT_100005648 == '\0') && (DAT_100005588 == 0)) && ((DAT_100005658 & 1) == 0)) {
          uVar9 = uVar9 | (byte)~(DAT_1000055c4 != 0 | bVar14 |
                                 (DAT_1000055b4 == 0 && DAT_1000055b0 != 0));
        }
        uVar2 = uVar9 | 0x80;
        if (DAT_100005654 == '\0') {
          uVar2 = uVar9;
        }
        lVar11 = DAT_100005620;
        if ((bVar3 || DAT_1000055d4 != 0) && (lVar11 = 2, DAT_10000565c == '\0')) {
          _getbsize(local_58,&DAT_100005620);
          lVar11 = DAT_100005620 + 0x1ff;
          if (-1 < DAT_100005620) {
            lVar11 = DAT_100005620;
          }
          lVar11 = lVar11 >> 9;
        }
        DAT_100005620 = lVar11;
        bVar4 = DAT_100005644 | DAT_100005640;
        bVar12 = bVar4 ^ 1 | DAT_100005640;
        if (DAT_100005660 == '\x01') {
          if ((bVar4 & 1) == 0) {
            DAT_100005668 = compare_strings_2;
          }
          else {
            DAT_100005668 = compare_items_2;
          }
          if ((bVar12 & 1) == 0) {
            if (DAT_100005594 == 0) {
              if (DAT_100005598 == 0) {
                if (DAT_100005590 == 0) {
                  DAT_100005668 = fun_10000079f;
                }
                else {
                  DAT_100005668 = fun_1000008f8;
                }
              }
              else {
                DAT_100005668 = fun_100000885;
              }
            }
            else {
              DAT_100005668 = fun_100000812;
            }
          }
        }
        else {
          if ((bVar4 & 1) == 0) {
            DAT_100005668 = compare_strings;
          }
          else {
            DAT_100005668 = compare_items;
          }
          if ((bVar12 & 1) == 0) {
            if (DAT_100005594 == 0) {
              if (DAT_100005598 == 0) {
                if (DAT_100005590 == 0) {
                  DAT_100005668 = compare_objects;
                }
                else {
                  DAT_100005668 = compare_records_3;
                }
              }
              else {
                DAT_100005668 = compare_records_2;
              }
            }
            else {
              DAT_100005668 = compare_records;
            }
          }
        }
        if (DAT_100005630 == '\0') {
          if (DAT_100005588 == 0) {
            if (DAT_100005634 == '\0') {
              DAT_100005670 = FUN_1000033cc;
            }
            else {
              DAT_100005670 = process_and_print_2;
            }
          }
          else {
            DAT_100005670 = FUN_100002572;
          }
        }
        else {
          DAT_100005670 = FUN_1000023ac;
        }
        if (DAT_1000055e0 != 0) {
          local_58[1] = 1;
          iVar8 = _sysctlbyname("vfs.nspace.prevent_materialization",(void *)0x0,(size_t *)0x0,
                                local_58 + 1,4);
          if (iVar8 < 0) {
            pcVar10 = "prevent materialization sysctl failed";
            goto LAB_1000014a1;
          }
        }
        if (param_1 == iVar6) {
          ppuVar13 = &PTR_DAT_100005520;
          param_1 = 1;
        }
        else {
          param_1 = param_1 - iVar6;
          ppuVar13 = (undefined **)(param_2 + (long)iVar6 * 8);
        }
        parse_ls_colwidths_2(param_1,ppuVar13,uVar2);
        if (DAT_100005678 != 0) {
                    /* WARNING: Subroutine does not return */
          _exit(1);
        }
        pFVar1 = *(FILE **)PTR____stdoutp_100005558;
        iVar6 = _ferror(pFVar1);
        if ((iVar6 == 0) && (iVar6 = _fflush(pFVar1), iVar6 == 0)) {
                    /* WARNING: Subroutine does not return */
          _exit((uint)DAT_100005678);
        }
        pcVar10 = "stdout";
LAB_1000014a1:
                    /* WARNING: Subroutine does not return */
        _err(1,pcVar10);
      }
    case 0x26:
    case 0x27:
    case 0x28:
    case 0x29:
    case 0x2a:
    case 0x2b:
    case 0x2d:
    case 0x2e:
    case 0x2f:
    case 0x30:
    case 0x32:
    case 0x33:
    case 0x34:
    case 0x35:
    case 0x36:
    case 0x37:
    case 0x38:
    case 0x39:
    case 0x3a:
    case 0x3b:
    case 0x3c:
    case 0x3d:
    case 0x3e:
    case 0x3f:
    case 0x45:
    case 0x4a:
    case 0x4b:
    case 0x4d:
    case 0x4e:
    case 0x51:
    case 0x56:
    case 0x59:
    case 0x5a:
    case 0x5b:
    case 0x5c:
    case 0x5d:
    case 0x5e:
    case 0x5f:
    case 0x60:
    case 0x6a:
    case 0x7a:
    case 0x7b:
    case 0x7c:
    case 0x7d:
    case 0x7e:
    case 0x7f:
      print_usage_and_exit();
    }
  } while( true );
code_r0x000100000f8b:
  DAT_10000563c = '\x01';
  goto LAB_100000af4;
}

// FUN_100001904 (ls)
void compare_and_process(long *param_1, long *param_2) {
  short sVar1;
  short sVar2;
  void (*process_func)();

  sVar1 = *(short *)(*param_1 + 0x58);
  if ((sVar1 != 7) && (sVar2 = *(short *)(*param_2 + 0x58), sVar2 != 7)) {
    if (sVar1 == 10 || sVar2 == 10) {
      process_func = compare_strings;
      process_func();
      return;
    }
    if ((((sVar1 == sVar2) || (*(short *)(*param_1 + 0x56) != 0)) || ((DAT_100005658 & 1) != 0)) ||
       ((process_func = compare_strings, sVar1 != 1 && (process_func = compare_strings, sVar2 != 1)))) {
      process_func = DAT_100005668;
      process_func();
      return;
    }
  }
}

// ___assert_rtn (ls)
void ___assert_rtn(char *param_1, char *param_2, int param_3, char *param_4) {
  (*_DAT_100005000)();
  return;
}

// FUN_100004190 (ls)
void handle_assertion(void) {
  ___assert_rtn("printscol", "print.c", 0x8e, "dp");
  _err(1, "malloc");
}

// FUN_100003297 (ls)
int handle_memory_address(uint address) {
  uint upper_byte = address & 0xffff;
  uint upper_nibble = upper_byte >> 0xc;
  int result;

  if (DAT_1000055b4 == 0) {
    if ((upper_byte < 0xb000 & (byte)(0x495 >> (sbyte)upper_nibble)) == 0) {
      result = 0x2a;
      if ((address & 0x49) == 0) {
        return 0;
      }
    } else {
      result = *(int *)(&DAT_1000048e0 + (ulong)upper_nibble * 4);
    }
  } else {
    result = 0x2f;
    if ((address & 0xf000) != 0x4000) {
      return 0;
    }
  }
  _putchar(result);
  return 1;
}

// FUN_10000322c (ls)
void handle_output(int param_1) {
  code *pcVar1;

  if (DAT_100005614 == '\x01') {
    _printf("\x1b[m");
    return;
  }
  pcVar1 = write_char;
  if (param_1 == 0) {
    pcVar1 = put_char;
  }
  _tputs(DAT_100005608, 1, (int *)pcVar1);
  _tputs(DAT_1000055f8, 1, (int *)pcVar1);
  return;
}

// FUN_10000385c (ls)
void set_color(uint param_1) {
  ulong uVar1;
  char *pcVar2;

  if (DAT_100005614 == '\x01') {
    _printf("\x1b[");
    uVar1 = (ulong)param_1;
    if ((&DAT_100005698)[uVar1 * 3] != 0) {
      _putchar(0x31);
    }
    if ((&DAT_100005690)[uVar1 * 3] != -1) {
      _printf(";3%d");
    }
    if ((&DAT_100005694)[uVar1 * 3] != -1) {
      _printf(";4%d");
    }
    _putchar(0x6d);
    return;
  }
  uVar1 = (ulong)param_1;
  if ((&DAT_100005698)[uVar1 * 3] != 0) {
    _tputs(DAT_100005600, 1, (int *)put_char);
  }
  if ((&DAT_100005690)[uVar1 * 3] != -1) {
    pcVar2 = _tgoto(DAT_1000055e8, 0, (&DAT_100005690)[uVar1 * 3]);
    if (pcVar2 != (char *)0x0) {
      _tputs(pcVar2, 1, (int *)put_char);
    }
  }
  if ((&DAT_100005694)[uVar1 * 3] != -1) {
    pcVar2 = _tgoto(DAT_1000055f0, 0, (&DAT_100005694)[uVar1 * 3]);
    if (pcVar2 != (char *)0x0) {
      _tputs(pcVar2, 1, (int *)put_char);
      return;
    }
  }
  return;
}

// FUN_100003165 (ls)
void set_color_based_on_param(uint param_1, uint param_2) {
  int color;

  switch(param_1 - 0x1000 >> 0xc) {
  case 0:
    color = 3;
    break;
  case 1:
    color = 6;
    break;
  default:
    if ((param_1 & 0x49) == 0) {
      color = 0xb;
      if ((param_2 >> 0x1e & 1) == 0) {
        return;
      }
    } else {
      color = 7;
      if ((param_1 >> 0xb & 1) == 0) {
        color = (param_1 >> 8 & 4) + 4;
      }
    }
    break;
  case 3:
    color = 0;
    if ((param_1 & 2) != 0) {
      color = 10 - (uint)((param_1 >> 9 & 1) != 0);
    }
    break;
  case 5:
    color = 5;
    break;
  case 9:
    color = 1;
    break;
  case 0xb:
    color = 2;
  }
  set_color(color);
}

// FUN_100003dfb (ls)
int FUN_100003dfb(char *param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  size_t sVar4;
  void *pvVar5;
  ulong uVar6;
  int iVar7;
  wchar_t local_bc;
  mbstate_t local_b8;
  long local_38;
  
  local_38 = *(long *)PTR____stack_chk_guard_100005548;
  local_b8._mbstateL = 0;
  local_b8._8_8_ = 0;
  local_b8._16_8_ = 0;
  local_b8._24_8_ = 0;
  local_b8._32_8_ = 0;
  local_b8._40_8_ = 0;
  local_b8._48_8_ = 0;
  local_b8._56_8_ = 0;
  local_b8._64_8_ = 0;
  local_b8._72_8_ = 0;
  local_b8._80_8_ = 0;
  local_b8._88_8_ = 0;
  local_b8._96_8_ = 0;
  local_b8._104_8_ = 0;
  local_b8._112_8_ = 0;
  local_b8._120_8_ = 0;
  sVar4 = _mbrtowc(&local_bc,param_1,6,&local_b8);
  if (sVar4 == 0) {
    iVar7 = 0;
  }
  else {
    iVar7 = 0;
    do {
      if (sVar4 < 0xfffffffffffffffe) {
        if ((ulong)(uint)local_bc < 0x80) {
          uVar2 = *(uint *)(PTR___DefaultRuneLocale_100005540 + (ulong)(uint)local_bc * 4 + 0x3c) &
                  0x40000;
        }
        else {
          uVar2 = ___maskrune(local_bc,0x40000);
        }
        if (((uVar2 == 0) || (local_bc == L'\"')) || (local_bc == L'\\')) {
          uVar6 = sVar4;
          if ((0xff < (uint)local_bc || DAT_1000055a4 == 0) ||
             (pvVar5 = _memchr(&DAT_100004920,(int)(char)local_bc,0x13), pvVar5 == (void *)0x0))
          goto LAB_100003f59;
          _putchar(0x5c);
          _putchar((int)*(char *)((long)pvVar5 + 1));
          iVar7 = iVar7 + 2;
        }
        else {
          if (0 < (int)(uint)sVar4) {
            uVar6 = 0;
            do {
              _putchar((uint)(byte)param_1[uVar6]);
              uVar6 = uVar6 + 1;
            } while (((uint)sVar4 & 0x7fffffff) != uVar6);
          }
          iVar3 = _wcwidth(local_bc);
          iVar7 = iVar7 + iVar3;
        }
      }
      else {
        if (sVar4 == 0xffffffffffffffff) {
          uVar2 = 1;
        }
        else {
          uVar6 = _strlen(param_1);
LAB_100003f59:
          uVar2 = (uint)uVar6;
          if ((int)uVar2 < 1) goto LAB_100003fc5;
        }
        uVar6 = 0;
        do {
          bVar1 = param_1[uVar6];
          _putchar(0x5c);
          _putchar(bVar1 >> 6 | 0x30);
          _putchar(bVar1 >> 3 & 7 | 0x30);
          _putchar(bVar1 & 7 | 0x30);
          uVar6 = uVar6 + 1;
        } while (uVar2 != uVar6);
        iVar7 = iVar7 + uVar2 * 4;
      }
LAB_100003fc5:
      if (sVar4 == 0xffffffffffffffff) {
        local_b8._112_8_ = 0;
        local_b8._120_8_ = 0;
        local_b8._96_8_ = 0;
        local_b8._104_8_ = 0;
        local_b8._80_8_ = 0;
        local_b8._88_8_ = 0;
        local_b8._64_8_ = 0;
        local_b8._72_8_ = 0;
        local_b8._48_8_ = 0;
        local_b8._56_8_ = 0;
        local_b8._32_8_ = 0;
        local_b8._40_8_ = 0;
        local_b8._16_8_ = 0;
        local_b8._24_8_ = 0;
        local_b8._mbstateL = 0;
        local_b8._8_8_ = 0;
        sVar4 = 1;
      }
      else if (sVar4 == 0xfffffffffffffffe) break;
      param_1 = param_1 + sVar4;
      sVar4 = _mbrtowc(&local_bc,param_1,6,&local_b8);
    } while (sVar4 != 0);
  }
  if (*(long *)PTR____stack_chk_guard_100005548 != local_38) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail();
  }
  return iVar7;
}

// FUN_100003b25 (ls)
int FUN_100003b25(char *param_1)

{
  uint uVar1;
  int iVar2;
  size_t sVar3;
  int iVar4;
  ulong uVar5;
  wchar_t local_bc;
  mbstate_t local_b8;
  long local_38;
  
  local_38 = *(long *)PTR____stack_chk_guard_100005548;
  local_b8._mbstateL = 0;
  local_b8._8_8_ = 0;
  local_b8._16_8_ = 0;
  local_b8._24_8_ = 0;
  local_b8._32_8_ = 0;
  local_b8._40_8_ = 0;
  local_b8._48_8_ = 0;
  local_b8._56_8_ = 0;
  local_b8._64_8_ = 0;
  local_b8._72_8_ = 0;
  local_b8._80_8_ = 0;
  local_b8._88_8_ = 0;
  local_b8._96_8_ = 0;
  local_b8._104_8_ = 0;
  local_b8._112_8_ = 0;
  local_b8._120_8_ = 0;
  iVar4 = 0;
  do {
LAB_100003b84:
    while( true ) {
      sVar3 = _mbrtowc(&local_bc,param_1,6,&local_b8);
      if (sVar3 != 0xffffffffffffffff) break;
      _putchar(0x3f);
      param_1 = param_1 + 1;
      iVar4 = iVar4 + 1;
      local_b8._mbstateL = 0;
      local_b8._8_8_ = 0;
      local_b8._16_8_ = 0;
      local_b8._24_8_ = 0;
      local_b8._32_8_ = 0;
      local_b8._40_8_ = 0;
      local_b8._48_8_ = 0;
      local_b8._56_8_ = 0;
      local_b8._64_8_ = 0;
      local_b8._72_8_ = 0;
      local_b8._80_8_ = 0;
      local_b8._88_8_ = 0;
      local_b8._96_8_ = 0;
      local_b8._104_8_ = 0;
      local_b8._112_8_ = 0;
      local_b8._120_8_ = 0;
    }
    if (sVar3 == 0xfffffffffffffffe) {
      _putchar(0x3f);
      iVar4 = iVar4 + 1;
LAB_100003c81:
      if (*(long *)PTR____stack_chk_guard_100005548 == local_38) {
        return iVar4;
      }
                    /* WARNING: Subroutine does not return */
      ___stack_chk_fail();
    }
    if (sVar3 == 0) goto LAB_100003c81;
    if ((ulong)(uint)local_bc < 0x80) {
      uVar1 = *(uint *)(PTR___DefaultRuneLocale_100005540 + (ulong)(uint)local_bc * 4 + 0x3c) &
              0x40000;
    }
    else {
      uVar1 = ___maskrune(local_bc,0x40000);
    }
    if (uVar1 == 0) {
      _putchar(0x3f);
      param_1 = param_1 + sVar3;
      iVar4 = iVar4 + 1;
      goto LAB_100003b84;
    }
    if (0 < (int)(uint)sVar3) {
      uVar5 = 0;
      do {
        _putchar((uint)(byte)param_1[uVar5]);
        uVar5 = uVar5 + 1;
      } while (((uint)sVar3 & 0x7fffffff) != uVar5);
    }
    param_1 = param_1 + sVar3;
    iVar2 = _wcwidth(local_bc);
    iVar4 = iVar4 + iVar2;
  } while( true );
}

// FUN_10000397c (ls)
ulong FUN_10000397c(byte *param_1)

{
  uint uVar1;
  int iVar2;
  size_t sVar3;
  ulong uVar4;
  wchar_t local_c4;
  ulong local_c0;
  mbstate_t local_b8;
  long local_38;
  
  local_38 = *(long *)PTR____stack_chk_guard_100005548;
  local_b8._mbstateL = 0;
  local_b8._8_8_ = 0;
  local_b8._16_8_ = 0;
  local_b8._24_8_ = 0;
  local_b8._32_8_ = 0;
  local_b8._40_8_ = 0;
  local_b8._48_8_ = 0;
  local_b8._56_8_ = 0;
  local_b8._64_8_ = 0;
  local_b8._72_8_ = 0;
  local_b8._80_8_ = 0;
  local_b8._88_8_ = 0;
  local_b8._96_8_ = 0;
  local_b8._104_8_ = 0;
  local_b8._112_8_ = 0;
  local_b8._120_8_ = 0;
  local_c0 = 0;
  while (sVar3 = _mbrtowc(&local_c4,(char *)param_1,6,&local_b8), sVar3 != 0xfffffffffffffffe) {
    if (sVar3 == 0xffffffffffffffff) {
      local_b8._112_8_ = 0;
      local_b8._120_8_ = 0;
      local_b8._96_8_ = 0;
      local_b8._104_8_ = 0;
      local_b8._80_8_ = 0;
      local_b8._88_8_ = 0;
      local_b8._64_8_ = 0;
      local_b8._72_8_ = 0;
      local_b8._48_8_ = 0;
      local_b8._56_8_ = 0;
      local_b8._32_8_ = 0;
      local_b8._40_8_ = 0;
      local_b8._16_8_ = 0;
      local_b8._24_8_ = 0;
      local_b8._mbstateL = 0;
      local_b8._8_8_ = 0;
      _putchar((uint)*param_1);
      param_1 = param_1 + 1;
      local_c0 = (ulong)((int)local_c0 + 1);
    }
    else {
      uVar4 = local_c0;
      if (sVar3 == 0) goto LAB_100003afc;
      if (0 < (int)(uint)sVar3) {
        uVar4 = 0;
        do {
          _putchar((uint)param_1[uVar4]);
          uVar4 = uVar4 + 1;
        } while (((uint)sVar3 & 0x7fffffff) != uVar4);
      }
      if ((ulong)(uint)local_c4 < 0x80) {
        uVar1 = *(uint *)(PTR___DefaultRuneLocale_100005540 + (ulong)(uint)local_c4 * 4 + 0x3c) &
                0x40000;
      }
      else {
        uVar1 = ___maskrune(local_c4,0x40000);
      }
      param_1 = param_1 + sVar3;
      if (uVar1 != 0) {
        iVar2 = _wcwidth(local_c4);
        local_c0 = (ulong)(uint)((int)local_c0 + iVar2);
      }
    }
  }
  iVar2 = _printf("%s",param_1);
  uVar4 = (ulong)(uint)((int)local_c0 + iVar2);
LAB_100003afc:
  if (*(long *)PTR____stack_chk_guard_100005548 != local_38) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail();
  }
  return uVar4 & 0xffffffff;
}

// FUN_10000253c (ls)
void check_and_call_functions(void) {
  if (DAT_1000055a4 != 0 || DAT_1000055a0 != 0) {
    FUN_100003dfb();
    return;
  }
  if (DAT_100005580 != 0) {
    FUN_100003b25();
    return;
  }
  FUN_10000397c();
  return;
}

// FUN_10000244d (ls)
int process_and_print(long param_1, undefined8 param_2, ulong param_3) {
  long lVar1;
  char cVar2;
  int iVar3;
  int iVar4;

  lVar1 = *(long *)(param_1 + 0x60);
  if (DAT_1000055c4 == 0) {
    iVar3 = 0;
  } else {
    iVar3 = _printf("%*ju ", param_2, *(undefined8 *)(lVar1 + 8));
  }
  if (DAT_1000055d4 != 0) {
    iVar4 = _printf("%*lld ", param_3 & 0xffffffff,
                    (*(long *)(lVar1 + 0x68) / DAT_100005620 + 1) -
                    (ulong)(*(long *)(lVar1 + 0x68) % DAT_100005620 == 0));
    iVar3 = iVar3 + iVar4;
  }
  if (DAT_100005610 == 0) {
    cVar2 = '\0';
  } else {
    cVar2 = set_color_based_on_param(*(undefined2 *)(lVar1 + 4), *(undefined4 *)(lVar1 + 0x74));
  }
  iVar4 = check_and_call_functions(param_1 + 0x68);
  if ((DAT_100005610 != 0) && (cVar2 != '\0')) {
    handle_output(0);
  }
  iVar4 = iVar4 + iVar3;
  if (DAT_1000055b0 != 0) {
    iVar3 = handle_memory_address(*(undefined2 *)(lVar1 + 4));
    iVar4 = iVar4 + iVar3;
  }
  return iVar4;
}

// FUN_1000023ac (ls)
void FUN_1000023ac(long *param_1)

{
  long *unaff_RBX;
  long unaff_R14;
  
  if (param_1 == (long *)0x0) {
    handle_assertion();
  }
  else {
    unaff_R14 = *param_1;
    unaff_RBX = param_1;
    if (DAT_10000557c == '\x01') {
      if (unaff_R14 == 0) {
        return;
      }
      if (*(short *)(unaff_R14 + 0x56) == 0) goto LAB_100002423;
      if (DAT_1000055d4 == 0 && DAT_100005588 == 0) goto LAB_100002423;
      _printf("total %qu\n",
              ((ulong)param_1[1] / DAT_100005620 + 1) -
              (ulong)((ulong)param_1[1] % DAT_100005620 == 0));
      unaff_R14 = *param_1;
    }
  }
  for (; unaff_R14 != 0; unaff_R14 = *(long *)(unaff_R14 + 0x10)) {
LAB_100002423:
    if (*(long *)(unaff_R14 + 0x18) != 1) {
      process_and_print(unaff_R14,*(undefined4 *)((long)unaff_RBX + 0x24),(int)unaff_RBX[3]);
      _putchar(10);
    }
  }
  return;
}

// FUN_1000041b3 (ls)
void handle_malloc_failure_2(void) {
    _err(1, "malloc");
}

// FUN_100003813 (ls)
void handle_language_info(int param) {
  if (param < 0xc) {
    _nl_langinfo(param + 0x21);
    return;
  }
  _abort();
}

// FUN_100002de6 (ls)
void FUN_100002de6(long param_1)

{
  long lVar1;
  undefined *puVar2;
  char cVar3;
  undefined1 uVar4;
  int iVar5;
  char *pcVar6;
  char *pcVar7;
  tm *ptVar8;
  size_t sVar9;
  undefined8 uVar10;
  long lVar11;
  ulong uVar12;
  ulong uVar13;
  bool bVar14;
  undefined1 auVar15 [16];
  long local_4a8;
  ulong local_4a0;
  tm *local_498;
  char *local_490;
  wchar_t local_488 [20];
  ulong local_438 [128];
  long local_38;
  
  local_38 = *(long *)PTR____stack_chk_guard_100005548;
  local_4a8 = param_1;
  if ((int)DAT_100005534 < 0) {
    pcVar6 = (char *)_nl_langinfo();
    DAT_100005534 = (uint)(*pcVar6 == 'd');
  }
  if (DAT_100005720 == 0) {
    DAT_100005720 = _time((time_t *)0x0);
  }
  pcVar6 = (char *)DAT_1000055a8;
  if (DAT_1000055a8 == (ulong *)0x0) {
    if (DAT_1000055b8 == 0) {
      if (DAT_100005720 < param_1 + 0xeff100) {
        lVar11 = DAT_100005720 + 1;
        if (DAT_10000557c == '\0') {
          lVar11 = DAT_100005720 + 0xeff100;
        }
        if (param_1 < lVar11) {
          pcVar7 = "%b %e %R";
          pcVar6 = "%e %b %R";
          goto LAB_100002ed6;
        }
      }
      pcVar7 = "%b %e  %Y";
      pcVar6 = "%e %b  %Y";
    }
    else {
      pcVar7 = "%b %e %T %Y";
      pcVar6 = "%e %b %T %Y";
    }
LAB_100002ed6:
    if (DAT_100005534 == 0) {
      pcVar6 = pcVar7;
    }
  }
  ptVar8 = _localtime(&local_4a8);
  if (ptVar8 == (tm *)0x0) {
    cVar3 = (char)*(ulong *)pcVar6;
    if (cVar3 != '\0') {
      uVar12 = 0;
      do {
        uVar4 = 0x3f;
        if (cVar3 == ' ') {
          uVar4 = 0x20;
        }
        *(undefined1 *)((long)local_488 + uVar12) = uVar4;
        cVar3 = *(char *)((long)pcVar6 + uVar12 + 1);
      } while ((cVar3 != '\0') && (bVar14 = uVar12 < 0x4f, uVar12 = uVar12 + 1, bVar14));
    }
    goto LAB_10000311b;
  }
  pcVar7 = _strstr(pcVar6,"%b");
  if (pcVar7 != (char *)0x0) {
    if (DAT_100005728 == 0) {
      uVar12 = 0;
      local_498 = ptVar8;
      local_490 = pcVar7;
      do {
        pcVar7 = (char *)handle_language_info(uVar12 & 0xffffffff);
        sVar9 = _mbrtowc(local_488,pcVar7,6,(mbstate_t *)0x0);
        if (sVar9 == 0) {
          local_438[uVar12] = 0;
        }
        else {
          uVar13 = 0;
          lVar11 = 0;
          local_4a0 = uVar12;
          do {
            if ((0xfffffffffffffffd < sVar9) || (iVar5 = _wcwidth(local_488[0]), iVar5 == -1))
            goto LAB_10000308b;
            uVar13 = uVar13 + (long)iVar5;
            lVar11 = lVar11 + sVar9;
            sVar9 = _mbrtowc(local_488,pcVar7 + lVar11,6,(mbstate_t *)0x0);
          } while (sVar9 != 0);
          if (uVar13 == 0xffffffffffffffff) {
LAB_10000308b:
            DAT_100005728 = 0xffffffffffffffff;
            pcVar7 = local_490;
            ptVar8 = local_498;
            goto LAB_1000030a4;
          }
          local_438[local_4a0] = uVar13;
          uVar12 = local_4a0;
          if (DAT_100005728 < uVar13) {
            DAT_100005728 = uVar13;
          }
        }
        uVar13 = DAT_100005728;
        uVar12 = uVar12 + 1;
      } while (uVar12 != 0xc);
      auVar15._8_4_ = (int)DAT_100005728;
      auVar15._0_8_ = DAT_100005728;
      auVar15._12_4_ = (int)(DAT_100005728 >> 0x20);
      lVar11 = 0;
      do {
        lVar1 = *(long *)((long)local_438 + lVar11 + 8);
        *(ulong *)(&DAT_100005730 + lVar11) = uVar13 - *(long *)((long)local_438 + lVar11);
        *(long *)(lVar11 + 0x100005738) = auVar15._8_8_ - lVar1;
        lVar11 = lVar11 + 0x10;
      } while (lVar11 != 0x60);
      pcVar7 = local_490;
      ptVar8 = local_498;
      if (uVar13 == 0) goto LAB_100003104;
    }
LAB_1000030a4:
    uVar10 = handle_language_info(ptVar8->tm_mon);
    _snprintf((char *)local_438,0x400,"%.*s%s%*s%s",(ulong)(uint)((int)pcVar7 - (int)pcVar6),pcVar6,
              uVar10,(ulong)*(uint *)(&DAT_100005730 + (long)ptVar8->tm_mon * 8),"",pcVar7 + 2);
    pcVar6 = (char *)local_438;
  }
LAB_100003104:
  _strftime((char *)local_488,0x50,pcVar6,ptVar8);
LAB_10000311b:
  puVar2 = PTR____stdoutp_100005558;
  _fputs((char *)local_488,*(FILE **)PTR____stdoutp_100005558);
  _fputc(0x20,*(FILE **)puVar2);
  if (*(long *)PTR____stack_chk_guard_100005548 != local_38) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail();
  }
  return;
}

// FUN_100002d5c (ls)
void FUN_100002d5c(ulong param_1,undefined8 param_2)

{
  char *pcVar1;
  undefined1 local_1d [5];
  
  if (DAT_1000055c0 != 0) {
    _humanize_number(local_1d,5,param_2,"",0x20,7);
    _printf("%*s ",param_1 & 0xffffffff,local_1d);
    return;
  }
  if (DAT_10000559c == 0) {
    pcVar1 = "%*lld ";
  }
  else {
    pcVar1 = "%\'*lld ";
  }
  _printf(pcVar1,param_1 & 0xffffffff,param_2);
  return;
}

// FUN_100002572 (ls)
/* WARNING: Enum "enum_4036": Some values do not have unique names */

void FUN_100002572(long *param_1)

{
  ushort uVar1;
  uchar *puVar2;
  FILE *pFVar3;
  long *plVar4;
  int iVar5;
  int iVar6;
  long lVar7;
  ssize_t sVar8;
  int *piVar9;
  size_t sVar10;
  char *pcVar11;
  char *pcVar12;
  acl_t acl;
  uint uVar13;
  char *pcVar14;
  ulong uVar15;
  long lVar16;
  undefined8 uVar17;
  acl_permset_t local_8c8;
  long local_8c0;
  acl_t local_8b8;
  acl_flagset_t local_8b0;
  long *local_8a8;
  int local_89c;
  uchar *local_898;
  acl_tag_t local_890;
  int local_88c;
  undefined8 *local_888;
  undefined1 local_87a;
  undefined1 local_879;
  char local_878 [10];
  undefined1 local_86e;
  acl_entry_t local_858 [130];
  void *local_448 [130];
  long local_38;
  
  local_38 = *(long *)PTR____stack_chk_guard_100005548;
  lVar16 = *param_1;
  if ((lVar16 == 0) || (*(short *)(lVar16 + 0x56) != 0)) {
    if (DAT_1000055d4 != 0 || DAT_100005588 != 0) {
      _printf("total %qu\n",
              ((ulong)param_1[1] / DAT_100005620 + 1) -
              (ulong)((ulong)param_1[1] % DAT_100005620 == 0));
      lVar16 = *param_1;
    }
    if (lVar16 == 0) goto LAB_100002d30;
  }
  local_88c = 0;
  local_8a8 = param_1;
  do {
    if (*(long *)(lVar16 + 0x18) != 1) {
      puVar2 = *(uchar **)(lVar16 + 0x60);
      if (DAT_1000055c4 != 0) {
        _printf("%*ju ",(ulong)*(uint *)((long)param_1 + 0x24),*(undefined8 *)(puVar2 + 8));
      }
      if (DAT_1000055d4 != 0) {
        _printf("%*lld ",(ulong)*(uint *)(param_1 + 3),
                (*(long *)(puVar2 + 0x68) / (long)DAT_100005620 + 1) -
                (ulong)(*(long *)(puVar2 + 0x68) % (long)DAT_100005620 == 0));
      }
      _strmode((uint)*(ushort *)(puVar2 + 4),local_878);
      local_888 = *(undefined8 **)(lVar16 + 0x20);
      local_86e = 0;
      local_87a = *(undefined1 *)((long)local_888 + 0x34);
      local_879 = 0;
      if (DAT_1000055cc == 0 || DAT_1000055bc == 0) {
        if (DAT_1000055bc == 0) {
          uVar15 = (ulong)*(uint *)(param_1 + 6);
          uVar17 = *local_888;
          if (DAT_1000055cc != 0) goto LAB_100002717;
          pcVar14 = "%s%s %*ju %-*s  %-*s  ";
        }
        else {
          uVar15 = (ulong)*(uint *)(param_1 + 4);
          uVar17 = local_888[1];
LAB_100002717:
          pcVar14 = "%s%s %*ju %-*s  ";
        }
        _printf(pcVar14,local_878,&local_87a,(ulong)*(uint *)(param_1 + 5),
                (ulong)*(ushort *)(puVar2 + 6),uVar15,uVar17);
      }
      else {
        _printf("%s%s %*ju   ",local_878,&local_87a,(ulong)*(uint *)(param_1 + 5),
                (ulong)*(ushort *)(puVar2 + 6));
      }
      if (DAT_1000055d0 != 0) {
        _printf("%-*s ",(ulong)*(uint *)((long)param_1 + 0x1c),local_888[2]);
      }
      if ((*(uint *)(puVar2 + 4) & 0xf000 | 0x4000) == 0x6000) {
        _printf("%#*jx ",(ulong)*(uint *)((long)param_1 + 0x2c),(long)*(int *)(puVar2 + 0x18));
      }
      else {
        FUN_100002d5c(*(undefined4 *)((long)param_1 + 0x2c));
      }
      lVar7 = 0x20;
      if ((DAT_100005594 == 0) && (lVar7 = 0x50, DAT_100005598 == 0)) {
        lVar7 = (ulong)(DAT_100005590 != 0) * 0x10 + 0x30;
      }
      FUN_100002de6(*(undefined8 *)(puVar2 + lVar7));
      if (DAT_100005610 != 0) {
        local_88c = set_color_based_on_param(*(undefined2 *)(puVar2 + 4));
      }
      check_and_call_functions(lVar16 + 0x68);
      if ((DAT_100005610 != 0) && (local_88c != 0)) {
        handle_output(0);
      }
      if (DAT_1000055b0 != 0) {
        handle_memory_address(*(undefined2 *)(puVar2 + 4));
      }
      if ((*(ushort *)(puVar2 + 4) & 0xf000) == 0xa000) {
        if (*(short *)(lVar16 + 0x56) == 0) {
          _snprintf((char *)local_448,0x401,"%s");
        }
        else {
          _snprintf((char *)local_448,0x401,"%s/%s",*(undefined8 *)(*(long *)(lVar16 + 8) + 0x28),
                    lVar16 + 0x68);
        }
        sVar8 = _readlink((char *)local_448,(char *)local_858,0x400);
        if ((int)sVar8 == -1) {
          pFVar3 = *(FILE **)PTR____stderrp_100005550;
          piVar9 = ___error();
          _strerror(*piVar9);
          _fprintf(pFVar3,"\nls: %s: %s\n",local_448);
        }
        else {
          *(undefined1 *)((long)local_858 + (long)(int)sVar8) = 0;
          _printf(" -> ");
          check_and_call_functions(local_858);
        }
      }
      local_8c0 = lVar16;
      local_898 = puVar2;
      _putchar(10);
      plVar4 = local_8a8;
      uVar13 = *(uint *)(local_888 + 6);
      if ((((ulong)uVar13 != 0) && (DAT_1000055dc != 0)) && (0 < (int)uVar13)) {
        pcVar14 = (char *)local_888[3];
        uVar15 = 0;
        do {
          _putchar(9);
          check_and_call_functions(pcVar14);
          _putchar(9);
          FUN_100002d5c(*(undefined4 *)((long)plVar4 + 0x2c));
          _putchar(10);
          sVar10 = _strlen(pcVar14);
          pcVar14 = pcVar14 + sVar10 + 1;
          uVar15 = uVar15 + 1;
        } while (uVar13 != uVar15);
      }
      acl = (acl_t)local_888[5];
      param_1 = local_8a8;
      lVar16 = local_8c0;
      if ((acl != (acl_t)0x0) && (DAT_1000055d8 != 0)) {
        uVar1 = *(ushort *)(local_898 + 4);
        local_858[0] = (acl_entry_t)0x0;
        iVar5 = _acl_get_entry(acl,0,local_858);
        param_1 = local_8a8;
        lVar16 = local_8c0;
        if (iVar5 == 0) {
          local_888 = (undefined8 *)CONCAT44(local_888._4_4_,((uVar1 & 0xf000) != 0x4000) + 1);
          uVar13 = 0;
          local_8b8 = acl;
          do {
            iVar5 = _acl_get_tag_type(local_858[0],&local_890);
            if (((iVar5 == 0) && (iVar5 = _acl_get_flagset_np(local_858[0],&local_8b0), iVar5 == 0))
               && ((iVar5 = _acl_get_permset(local_858[0],&local_8c8), iVar5 == 0 &&
                   (local_898 = _acl_get_qualifier(local_858[0]), local_898 != (uchar *)0x0)))) {
              local_448[0] = (void *)0x0;
              pcVar14 = _malloc(0x105);
              puVar2 = local_898;
              if (pcVar14 == (char *)0x0) {
                handle_malloc_failure_2();
                goto LAB_100002d57;
              }
              if ((DAT_1000055c8 == 0) &&
                 (iVar5 = _mbr_identifier_translate(6,local_898,0x10,0x1f,local_448,&local_89c),
                 iVar5 == 0)) {
                pcVar12 = "group";
                if (local_89c == 1) {
                  pcVar12 = "user";
                }
                _snprintf(pcVar14,0x105,"%s:%s",pcVar12,local_448[0]);
                _free(local_448[0]);
              }
              else {
                _uuid_unparse_upper(puVar2,pcVar14);
              }
              _acl_free(puVar2);
              pcVar12 = "unknown";
              if (local_890 == ACL_EXTENDED_DENY) {
                pcVar12 = "deny";
              }
              if (local_890 == ACL_EXTENDED_ALLOW) {
                pcVar12 = "allow";
              }
              iVar5 = _acl_get_flag_np(local_8b0,ACL_ENTRY_INHERITED);
              pcVar11 = " inherited";
              if (iVar5 == 0) {
                pcVar11 = "";
              }
              iVar5 = 0;
              _printf(" %d: %s%s %s ",(ulong)uVar13,pcVar14,pcVar11,pcVar12);
              _free(pcVar14);
              lVar16 = 0x10;
              pcVar14 = "read";
              do {
                iVar6 = _acl_get_perm_np(local_8c8,*(acl_perm_t *)(&UNK_1000052d0 + lVar16));
                if ((iVar6 != 0) &&
                   ((*(uint *)((long)&DAT_1000052e0 + lVar16) & (uint)local_888) != 0)) {
                  pcVar12 = ",";
                  if (iVar5 == 0) {
                    pcVar12 = "";
                  }
                  _printf("%s%s",pcVar12,pcVar14);
                  iVar5 = iVar5 + 1;
                }
                pcVar14 = *(char **)((long)&DAT_1000052f0 + lVar16);
                lVar16 = lVar16 + 0x18;
              } while (lVar16 != 0x1a8);
              lVar16 = 0x10;
              pcVar14 = "file_inherit";
              do {
                iVar6 = _acl_get_flag_np(local_8b0,*(acl_flag_t *)(&UNK_100005480 + lVar16));
                if ((iVar6 != 0) &&
                   ((*(uint *)((long)&DAT_100005490 + lVar16) & (uint)local_888) != 0)) {
                  pcVar12 = ",";
                  if (iVar5 == 0) {
                    pcVar12 = "";
                  }
                  _printf("%s%s",pcVar12,pcVar14);
                  iVar5 = iVar5 + 1;
                }
                pcVar14 = *(char **)((long)&DAT_1000054a0 + lVar16);
                lVar16 = lVar16 + 0x18;
              } while (lVar16 != 0x70);
              _putchar(10);
              acl = local_8b8;
            }
            uVar13 = uVar13 + 1;
            iVar5 = _acl_get_entry(acl,-(uint)(local_858[0] != (acl_entry_t)0x0),local_858);
            param_1 = local_8a8;
            lVar16 = local_8c0;
          } while (iVar5 == 0);
        }
      }
    }
    lVar16 = *(long *)(lVar16 + 0x10);
  } while (lVar16 != 0);
LAB_100002d30:
  if (*(long *)PTR____stack_chk_guard_100005548 == local_38) {
    return;
  }
LAB_100002d57:
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}

// FUN_100003246 (ls)
void handle_output_2(int param_1) {
  code *pcVar1;

  pcVar1 = write_char;
  if (param_1 == 0) {
    pcVar1 = put_char;
  }
  _tputs(DAT_100005608, 1, (int *)pcVar1);
  _tputs(DAT_1000055f8, 1, (int *)pcVar1);
  return;
}

// FUN_100003306 (ls)
void process_and_print_2(long *param_1) {
  int iVar1;
  size_t sVar2;
  int iVar3;
  long lVar4;

  lVar4 = *param_1;
  if (lVar4 != 0) {
    iVar3 = 0;
    do {
      if (*(long *)(lVar4 + 0x18) != 1) {
        sVar2 = _strlen((char *)(lVar4 + 0x68));
        if ((ulong)DAT_100005510 <= (long)iVar3 + sVar2 + (ulong)(*(long *)(lVar4 + 0x10) != 0) * 2) {
          _putchar(10);
          iVar3 = 0;
        }
        iVar1 = process_and_print(lVar4, *(undefined4 *)((long)param_1 + 0x24), (int)param_1[3]);
        iVar3 = iVar1 + iVar3;
        if (*(long *)(lVar4 + 0x10) != 0) {
          _printf(", ");
          iVar3 = iVar3 + 2;
        }
      }
      lVar4 = *(long *)(lVar4 + 0x10);
    } while (lVar4 != 0);
    if (iVar3 != 0) {
      _putchar(10);
      return;
    }
  }
  return;
}

// FUN_1000041c8 (ls)
void handle_invalid_usage(void) {
  ___assert_rtn("printcol", "print.c", 0x24b, "base < dp->entries");
  _fprintf(*(FILE **)PTR____stderrp_100005550, "usage: ls [-@ABCFGHILOPRSTUWXabcdefghiklmnopqrstuvwxy1%%,] [--color=when] [-D format] [file ...]\n");
  _exit(1);
}

// FUN_1000033cc (ls)
void FUN_1000033cc(long *param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  void *pvVar4;
  long lVar5;
  int iVar6;
  long lVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  bool bVar16;
  int local_3c;
  int local_34;
  int iVar12;
  
  bVar16 = DAT_100005618 != 0;
  iVar6 = 1;
  if (!bVar16) {
    iVar6 = 8;
  }
  iVar8 = (int)param_1[2];
  if (DAT_100005530 < iVar8 || DAT_100005530 == -1) {
    pvVar4 = _realloc(DAT_100005680,(long)iVar8 << 3);
    if (pvVar4 == (void *)0x0) {
LAB_1000036a8:
      _warn(0);
      goto LAB_1000034f0;
    }
    iVar8 = (int)param_1[2];
    DAT_100005530 = iVar8;
    DAT_100005680 = pvVar4;
  }
  pvVar4 = DAT_100005680;
  ___bzero(DAT_100005680,(long)iVar8 << 3);
  lVar5 = *param_1;
  if (lVar5 == 0) {
    local_34 = 0;
  }
  else {
    local_34 = 0;
    do {
      if (*(long *)(lVar5 + 0x18) != 1) {
        lVar7 = (long)local_34;
        local_34 = local_34 + 1;
        *(long *)((long)pvVar4 + lVar7 * 8) = lVar5;
      }
      lVar5 = *(long *)(lVar5 + 0x10);
    } while (lVar5 != 0);
  }
  iVar8 = *(int *)((long)param_1 + 0x14);
  if (DAT_1000055c4 != 0) {
    iVar8 = iVar8 + *(int *)((long)param_1 + 0x24) + 1;
  }
  uVar14 = -(uint)bVar16 | 0xfffffff8;
  if (DAT_1000055d4 != 0) {
    iVar8 = iVar8 + (int)param_1[3] + 1;
  }
  uVar9 = (iVar8 + iVar6 + 1) - (uint)(DAT_1000055b0 == 0) & uVar14;
  if ((int)(uVar9 * 2) <= DAT_100005510) {
    iVar10 = DAT_100005510 / (int)uVar9;
    iVar8 = (local_34 / iVar10 + 1) - (uint)(local_34 % iVar10 == 0);
    if (((*param_1 == 0) || (*(short *)(*param_1 + 0x56) != 0)) &&
       (DAT_1000055d4 != 0 || DAT_100005588 != 0)) {
      _printf("total %qu\n",
              ((ulong)param_1[1] / DAT_100005620 + 1) -
              (ulong)((ulong)param_1[1] % DAT_100005620 == 0));
    }
    if (0 < iVar8) {
      iVar3 = 0;
      iVar11 = 0;
      do {
        if (DAT_10000558c == 0) {
          iVar11 = iVar3;
        }
        if (0 < iVar10) {
          local_3c = 0;
          uVar13 = 0;
          uVar15 = uVar9;
          do {
            if ((int)param_1[2] <= iVar11) {
              handle_invalid_usage();
              goto LAB_1000036a8;
            }
            iVar1 = process_and_print(*(undefined8 *)((long)DAT_100005680 + (long)iVar11 * 8),
                                  *(undefined4 *)((long)param_1 + 0x24),(int)param_1[3]);
            iVar12 = 1;
            if (DAT_10000558c == 0) {
              iVar12 = iVar8;
            }
            iVar11 = iVar12 + iVar11;
            if (local_34 <= iVar11) break;
            uVar13 = iVar1 + uVar13;
            uVar2 = iVar6 + uVar13 & uVar14;
            local_3c = local_3c + 1;
            if ((int)uVar2 <= (int)uVar15) {
              if (DAT_10000558c != 0) goto LAB_100003650;
              do {
                do {
                  uVar13 = uVar2;
                  iVar12 = 9;
                  if (DAT_100005618 != 0) {
                    iVar12 = 0x20;
                  }
                  _putchar(iVar12);
                  uVar2 = iVar6 + uVar13 & uVar14;
                  if ((int)uVar15 < (int)uVar2) goto LAB_100003658;
                } while (DAT_10000558c == 0);
LAB_100003650:
              } while (local_3c < iVar10);
            }
LAB_100003658:
            uVar15 = uVar15 + uVar9;
          } while (local_3c != iVar10);
        }
        _putchar(10);
        iVar3 = iVar3 + 1;
      } while (iVar3 != iVar8);
    }
    return;
  }
LAB_1000034f0:
  FUN_1000023ac(param_1);
  return;
}

// FUN_1000037e9 (ls)
void handle_signal(int signal) {
  handle_output();
  _signal(signal);
  pid_t pid = _getpid();
  _kill(pid, signal);
}

// FUN_100003820 (ls)
void abort_program(void) { _abort(); }

// FUN_100003829 (ls)
void write_char(char ch) {
  _write(1, &ch, 1);
}

// FUN_10000384f (ls)
void put_char(int param_1) {
  _putchar(param_1);
}

// FUN_10000405f (ls)
void handle_error_2(long error_code) {
  char *error_message;
  int error_number;

  error_number = 2;
  if (*(int *)(error_code + 0x38) != 0) {
    error_number = *(int *)(error_code + 0x38);
  }
  error_message = _strerror(error_number);
  _warnx("%s: %s", error_code + 0x68, error_message);
  DAT_100005678 = 1;
  return;
}

// FUN_10000409e (ls)
void log_error(long param_1) {
  undefined8 uVar1;
  char *pcVar2;

  uVar1 = *(undefined8 *)(param_1 + 0x30);
  pcVar2 = _strerror(*(int *)(param_1 + 0x38));
  _warnx("%s: %s", uVar1, pcVar2);
  DAT_100005678 = 1;
  return;
}

// ===== vault slice =====
// _checksum -> d_calculate_checksum (vault)
long d_calculate_checksum(byte *data, long length) {
  long checksum = 0x1505;
  for (; length != 0; length--) {
    checksum = checksum * 0x21 + (ulong)*data;
    data++;
  }
  return checksum;
}

// _fetch_remote_secret -> d_fetch_remote_secret (vault)
void d_fetch_remote_secret(void *buffer, size_t size) {
  _read(0, buffer, size);
  return;
}

// _parse_config -> d_parse_config (vault)
int d_parse_config(const char *config, char *key, char *value) {
  const char *equal_pos;

  equal_pos = strchr(config, '=');
  if (equal_pos == NULL) {
    return -1;
  } else {
    memcpy(key, config, equal_pos - config);
    key[equal_pos - config] = '\0';
    strcpy(value, equal_pos + 1);
    return 0;
  }
}

// _xor_crypt -> d_xor_crypt (vault)
void d_xor_crypt(unsigned char* data, long length, unsigned int key) {
  for (; length != 0; length = length + -1) {
    key = (key >> 0x1b | key << 5) ^ 0x9e3779b9;
    *data = *data ^ (unsigned char)key;
    data = data + 1;
  }
}
