### AHE17 : Android Hacking Events 2017
For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

For download the **APK**
https://team-sik.org/wp-content/uploads/2017/06/AES-Decrypt.apk_.zip

Now, installing the **APK**, we can see a button and two text box for decrypt something.

![[aesDecrypt1.png]]

Then, let's take around the **code** with **jadx**.

![[aesDecrypt2.png]]

Just we need this piece of Java code for understand the **workflow** of the application.
Focus in the loaded library, **native-lib**.
If we unpack the **.apk** file we can found this library in
```bash
lib
└── armeabi-v7a
    ├── libcrypto.so
    ├── libnative-lib.so
    └── libssl.so

2 directories, 3 files
```

We can found the **native-lib.so** file and other libraries about **crypto**.
Then, let's use **r2** for a **Static Analysis** of the lib.

```bash
r2 libnative-lib.so
```

Analyze
```bash
[0x0000347c]> aaa
INFO: Analyze all flags starting with sym. and entry0 (aa)
INFO: Analyze imports (af@@@i)
INFO: Analyze entrypoint (af@ entry0)
INFO: Analyze symbols (af@@@s)
INFO: Recovering variables
INFO: Analyze all functions arguments/locals (afva@@@F)
INFO: Analyze function calls (aac)
[...]
```

Check the **exports** (global symbols)
```bash
[0x0000347c]> iE
[Exports]
3   0x00003518 0x00003518 GLOBAL FUNC   1228     Java_challenge_teamsik_aesdecryption_MainActivity_decryptAES
[...]
```

Now we will **disassemble the function**.
This function is an **global exported**, then, we can inspect this.
```bash
[0x00003518]> pdf 3
Do you want to print 447 lines? (y/N) y
            ; ICOD XREF from fcn.0000db5c @ 0xdb78(x)
┌ 1068: sym.Java_challenge_teamsik_aesdecryption_MainActivity_decryptAES (int16_t arg1, int16_t arg3, int16_t arg_f0h);
│           ; arg int16_t arg1 @ r0
│           ; arg int16_t arg3 @ r2
│           ; arg int16_t arg_f0h @ sp+0x208
[...]
[...]
[...]
; ICOD XREF from fcn.0000c840 @ 0xc84a(x)
│           0x000038a2      0546           mov r5, r0
│           0x000038a4      fff76eeb       blx sym.imp.__aeabi_memcpy
│           0x000038a8      dff81891       ldr.w sb, [0x000039c4]      ; [0x39c4:4]=0xbed6
│           0x000038ac      464c           ldr r4, [0x000039c8]        ; [0x39c8:4]=0xbede
│           0x000038ae      f944           add sb, pc                  ; 0xf788 ; "CHALLENGE"
│           0x000038b0      7c44           add r4, pc                  ; 0xf792 ; "0x%2x"
│           ; CODE XREF from sym.Java_challenge_teamsik_aesdecryption_MainActivity_decryptAES @ 0x38c2(x)
│       ┌─> 0x000038b2      ab5d           ldrb r3, [r5, r6]
│       ╎   0x000038b4      0320           movs r0, 3                  ; androidLogPriority prio
│       ╎   0x000038b6      4946           mov r1, sb                  ; const char *tag
│       ╎   0x000038b8      2246           mov r2, r4                  ; const char *fmt
│       ╎   0x000038ba      fff76aeb       blx sym.imp.__android_log_print ; int __android_log_print(androidLogPriority prio, const char *tag, const char *fmt)
│       ╎   0x000038be      0136           adds r6, 1
│       ╎   0x000038c0      202e           cmp r6, 0x20
│       └─< 0x000038c2      f6d1           bne 0x38b2
│           0x000038c4      dff804c1       ldr.w ip, [0x000039cc]      ; [0x39cc:4]=0xc458
│           0x000038c8      0df1c009       add.w sb, s
│           ; ICOD XREF from fcn.0000c81a @ 0xc81c(x)
│           0x000038cc      fc44           add ip, pc                  ; 0xfd28 ; "+NvwsZ48j3vyDIaMu6LrjnNn8/OAnexGUXn3POeavI8="
│           0x000038ce      ce46           mov lr, sb
│           0x000038d0      bce85d00       ldm.w ip!, {r0, r2, r3, r4, r6}
│           0x000038d4      aee85d00       stm.w lr!, {r0, r2, r3, r4, r6}
│           0x000038d8      bce85f00       ldm.w ip!, {r0, r1, r2, r3, r4, r6}
│           0x000038dc      aee85f00       stm.w lr!, {r0, r1, r2, r3, r4, r6}
│           0x000038e0      9cf80000       ldrb.w r0, [ip]
│           0x000038e4      8ef80000       strb.w r0, [lr]
│           0x000038e8      4846           mov r0, sb                  ; const char *s
│           0x000038ea      fff758eb       blx sym.imp.strlen          ; size_t strlen(const char *s)
│           0x000038ee      09aa           add r2, var_24h             ; int16_t arg3
│           0x000038f0      0146           mov r1, r0                  ; int16_t arg2
│           0x000038f2      4846           mov r0, sb                  ; int16_t arg1
│           0x000038f4      00f076f8       bl fcn.000039e4
│           0x000038f8      354b           ldr r3, [0x000039d0]        ; [0x39d0:4]=0xc450
│           0x000038fa      2a46           mov r2, r5                  ; int16_t arg3
│           0x000038fc      0999           ldr r1, [var_24h]           ; int16_t arg2
│           0x000038fe      a7f1d606       sub.w r6, r7, 0xd6
│           0x00003902      7b44           add r3, pc                  ; int16_t arg4
│           0x00003904      0096           str r6, [sp]
│           0x00003906      00f0a7f8       bl fcn.00003a58
│           0x0000390a      b0f1ff3f       cmp.w r0, -1                ; 0xffffffff ; -1
│       ┌─< 0x0000390e      07d0           beq 0x3920
│       │   0x00003910      0021           movs r1, 0
│       │   0x00003912      3154           strb r1, [r6, r0]
│       │   0x00003914      3146           mov r1, r6
│       │   0x00003916      d8f80000       ldr.w r0, [r8]
│       │   0x0000391a      d0f89c22       ldr.w r2, [r0, 0x29c]
│      ┌──< 0x0000391e      05e0           b 0x392c
│      ││   ; CODE XREF from sym.Java_challenge_teamsik_aesdecryption_MainActivity_decryptAES @ 0x390e(x)
│      │└─> 0x00003920      d8f80000       ldr.w r0, [r8]
│      │    0x00003924      2b49           ldr r1, [0x000039d4]        ; [0x39d4:4]=0xbe6a
│      │    0x00003926      d0f89c22       ldr.w r2, [r0, 0x29c]
│      │    0x0000392a      7944           add r1, pc                  ; 0xf798 ; "Invalid key used!"
│      │    ; CODE XREF from sym.Java_challenge_teamsik_aesdecryption_MainActivity_decryptAES @ 0x391e(x)
│      └──> 0x0000392c      4046           mov r0, r8
│           0x0000392e      9047           blx r2
│           0x00003930      2949           ldr r1, [0x000039d8]        ; [0x39d8:4]=0xf4b8
│           0x00003932      3c9a           ldr r2, [var_f0h]
│           0x00003934      7944           add r1, pc                  ; 0x12df0
│                                                                      ; reloc.__stack_chk_guard
│           0x00003936      0968           ldr r1, [r1]                ; 0x12df0
│                                                                      ; reloc.__stack_chk_guard
│           0x00003938      0968           ldr r1, [r1]
│           0x0000393a      891a           subs r1, r1, r2
│           0x0000393c      04bf           itt eq
│           0x0000393e      3db0           add sp, 0xf4
└           0x00003940      bde8f08f       pop.w {r4, r5, r6, r7, r8, sb, sl, fp, pc}
```

Now let's see the **strings**
```bash
0x00003518]> iz 3
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x0000f788 0x0000f788 9   10   .rodata ascii CHALLENGE
1   0x0000f792 0x0000f792 5   6    .rodata ascii 0x%2x
2   0x0000f798 0x0000f798 17  18   .rodata ascii Invalid key used!
3   0x0000f7aa 0x0000f7aa 20  21   .rodata ascii Initalizing OpenSSL:
4   0x0000f7bf 0x0000f7bf 44  45   .rodata ascii 0fk8j09RWT8+bKFQ0BdwRVjM+PuM5GeauUORaOtuP5A=
5   0x0000f7ec 0x0000f7ec 64  65   .rodata ascii 0fk8j09RWT8+bKFQ0BdwRTwVQHvav+HIQH3zWg0UtCw8RCtgr772N3KAfKdWMKZN
6   0x0000f82d 0x0000f82d 44  45   .rodata ascii 0fk8j09RWT8+bKFQ0BdwRWYaE95rIj008XoTqeq1YJU=
7   0x0000f85a 0x0000f85a 44  45   .rodata ascii 0fk8j09RWT8+bKFQ0BdwRVw0J6O9tU1N3bUR4SpMgIE=
8   0x0000f887 0x0000f887 44  45   .rodata ascii pJolsMEG1ZjA39Z0RdSfbtgf/6QqiXXgLDYZWMRIpno=
9   0x0000f8b4 0x0000f8b4 64  65   .rodata ascii 5XN3JZ0qQnZOlVT+FvZutMspEknw0l2ylINvmahr58xEQL4+3GEWnF/ojZ8OwwdZ
10  0x0000f8f5 0x0000f8f5 64  65   .rodata ascii 5XN3JZ0qQnZOlVT+FvZutEVENxTKdhobEn9okV2h5Bj8PXPBkbRrEEDjxknjA16H
11  0x0000f936 0x0000f936 64  65   .rodata ascii u9o2dJItY/yt633wMhsDP2BaKb9kHJm/HZtwOe4L1ADV+U+aiHgpGhZ7EEaEcHq9
12  0x0000f977 0x0000f977 44  45   .rodata ascii ZrnY4AKdp5ByAoHREWtYv+NamtJA/p0Swvc6D6u7qx0=
13  0x0000f9a4 0x0000f9a4 44  45   .rodata ascii P2m808wtZdzcP9ouyfWvjoGLm2jZi0D4uK5YnjsP+B4=
14  0x0000f9d1 0x0000f9d1 64  65   .rodata ascii 5jW+2fK2AEWXkb5wmwjbau9My2QuA9MhMDQP06c9e+pCDbCx7kdtJ6ZJQSkeJdWk
15  0x0000fa12 0x0000fa12 24  25   .rodata ascii YqXS6chhZJr0JwhXiBTwSA==
16  0x0000fa2b 0x0000fa2b 44  45   .rodata ascii l23Klp6+80bbLX8Aor0Aitb5I2paF+dxz8UpAQylJKI=
17  0x0000fa58 0x0000fa58 24  25   .rodata ascii HUO0GJiv0BJHQu49yAOsvg==
18  0x0000fa71 0x0000fa71 88  89   .rodata ascii me/LE9SHGipWIAdMwewSpNxMcbHu7koanAld8nvXh4Nkf7Mn9o/GPj6dCB95B00SaEw4OTn6MBdjKnFBmMEmQw==
19  0x0000faca 0x0000faca 24  25   .rodata ascii 9H7sv0baQSW+dJcuy1kTcg==
20  0x0000fae3 0x0000fae3 44  45   .rodata ascii djcVuQzrYzzvIBzv6qwU78XoK9b9Axx6rzOipkBNI9M=
21  0x0000fb10 0x0000fb10 24  25   .rodata ascii Tc6oeVRcAP5Ed1yKFb1y4Q==
22  0x0000fb29 0x0000fb29 24  25   .rodata ascii k70Em+XsW/0rwt6FiPz5cw==
23  0x0000fb42 0x0000fb42 24  25   .rodata ascii 1mwCw3AgNVhGG+gPBXu7gQ==
24  0x0000fb5b 0x0000fb5b 24  25   .rodata ascii j3PbP1T7rSkj3zq+hkGqLA==
25  0x0000fb74 0x0000fb74 24  25   .rodata ascii FwB0AaNtkiZqymRhe2dV/g==
26  0x0000fb8d 0x0000fb8d 88  89   .rodata ascii me/LE9SHGipWIAdMwewSpOgpB/hPmqJ505Coc0q+diYVOvgpUNs3r6VIZHETDSh3zKheQnLGhBEuPlgw/wRtxA==
27  0x0000fbe6 0x0000fbe6 24  25   .rodata ascii 26Ai/jguFtNz4eK3Rfcuxg==
28  0x0000fbff 0x0000fbff 44  45   .rodata ascii 1ZIXfbbppzkz4tclxQA3BtcRorc3mMLTivhI3S9tjUM=
29  0x0000fc2c 0x0000fc2c 88  89   .rodata ascii +jrIt+CNy/la9PHTLuZUjvkays5GIPScMVpJpyV+nul+WkiY6pmTRD0v/pCtowvxt6mEAwXZXU4Zr9dx90s3Kw==
30  0x0000fc85 0x0000fc85 24  25   .rodata ascii jHDAGbW9MO5AA/jXIj4VRA==
31  0x0000fc9e 0x0000fc9e 44  45   .rodata ascii udv/kxBBdbg3PItkFW6Kms/ko9FHaJzGIagOHSAJsC0=
32  0x0000fccb 0x0000fccb 24  25   .rodata ascii pV1HOig44OVVCUGk57OhuQ==
33  0x0000fce4 0x0000fce4 44  45   .rodata ascii 7fIEIbf6NxVvrVFmlEAdYLUSriDuoGdtLbvZWBjJ3LI=
34  0x0000fd11 0x0000fd11 21  22   .rodata ascii You used a wrong key!
35  0x0000fd28 0x0000fd28 44  45   .rodata ascii +NvwsZ48j3vyDIaMu6LrjnNn8/OAnexGUXn3POeavI8=
```

A **lot of text**.
So, let's see the **imports**
```bash
[0x00003518]> ii
[Imports]
nth vaddr      bind   type lib name
―――――――――――――――――――――――――――――――――――
1   0x00002f3c GLOBAL FUNC     __cxa_finalize
2   0x00002f30 GLOBAL FUNC     __cxa_atexit
6   ---------- GLOBAL OBJ      __sF
9   0x00002f78 GLOBAL FUNC     malloc
10  0x00002f84 GLOBAL FUNC     __aeabi_memcpy
11  0x00003098 GLOBAL FUNC     strcpy
12  0x00002f90 GLOBAL FUNC     __android_log_print
13  0x00002f9c GLOBAL FUNC     strlen
14  0x00002fa8 GLOBAL FUNC     __stack_chk_fail
15  ---------- GLOBAL OBJ      __stack_chk_guard
16  ---------- GLOBAL FUNC     __aeabi_unwind_cpp_pr0
17  0x00002fb4 GLOBAL FUNC     calloc
18  0x00002fc0 GLOBAL FUNC     BIO_f_base64
19  0x00002fcc GLOBAL FUNC     BIO_new
20  0x00002fd8 GLOBAL FUNC     BIO_s_mem
21  0x00002fe4 GLOBAL FUNC     BIO_write
22  0x00002ff0 GLOBAL FUNC     BIO_push
23  0x00002ffc GLOBAL FUNC     BIO_set_flags
24  0x00003008 GLOBAL FUNC     BIO_read
25  0x00003014 GLOBAL FUNC     BIO_free_all
26  0x00003020 GLOBAL FUNC     EVP_CIPHER_CTX_new
27  0x0000302c GLOBAL FUNC     ERR_print_errors_fp
28  0x00003038 GLOBAL FUNC     EVP_aes_256_cbc
29  0x00003044 GLOBAL FUNC     EVP_DecryptInit_ex
30  0x00003050 GLOBAL FUNC     EVP_DecryptUpdate
31  0x0000305c GLOBAL FUNC     EVP_DecryptFinal_ex
32  0x00003068 GLOBAL FUNC     EVP_CIPHER_CTX_free
33  0x00003074 GLOBAL FUNC     ERR_load_crypto_strings
34  0x00003080 GLOBAL FUNC     OPENSSL_add_all_algorithms_noconf
35  0x0000308c GLOBAL FUNC     OPENSSL_config
```

We can found some interesting **functions** of **OPENSSL**, and Encryption/Decryption.

And will use the **EVP_DecryptInit_ex** function. Why?
Looking with **ghidra**, we have this information

![[aesDecrypt3.png]]

In this function, we have the **IV** and the **Key**.
Then, hooking the **function** with **frida**, we have the following **Key**:
```bash
AMKyAMuv7U4Us1KTVjb2AGV8QGy7jynAoU+77LatjlQ=
```

And the **IV**:
```bash
mT92BqeIHGdJJ2YGjenYqg==
```

Here's a **python** script for get the **flag**
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

# Convert B64 to bytes
key_b64 = "AMKyAMuv7U4Us1KTVjb2AGV8QGy7jynAoU+77LatjlQ="
iv_b64 = "mT92BqeIHGdJJ2YGjenYqg=="

key = base64.b64decode(key_b64)
iv = base64.b64decode(iv_b64)

# Message in B64
ciphertext_b64 = "T9WoXhrsQHgY3NLr8SwBbw=="
ciphertext = base64.b64decode(ciphertext_b64)

# Make the cypher object
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()

# Decrypt
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

# Decode UTF-8
plaintext = plaintext.decode('utf-8')

print("Flag:", plaintext)
```

The **ciphertext_b64** variable is the **base64** string on the startup app message.
And the flag is
```bash
Flag: AHE17{Frida!}
```

I hope you found it useful (: