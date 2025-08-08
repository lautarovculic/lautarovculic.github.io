**Note**: For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

Download **APK**: https://lautarovculic.com/my_files/3778e43f21797bb383108182fe200a928be8605ff5b078aaf4feac02850b91f4
**Password**: infected

![[laby2016_cups1.png]]

After **extract** the file, we get the **.apk**
Install it with **adb**
```bash
adb install -r ezFill.apk
```

We can see a **login** activity
So, for **understand what the app do**, we need **decompile it**.
```bash
apktool d ezFill.apk
```
And open the **apk** file with **jadx** (GUI version)

We have just **one** activity in the package `mx.fill.ez.cups.ezfill`
The **CupsLogin** class is so extended. So I will show you just the **necessary** code for make this challenge.

We have some **hardcoded** usernames and password
```java
private static final String[] l = {"foo@example.com:hello", "bar@example.com:world", "tetris@nintendo.com:barre11$", "drltchie@bell.com:c4lif3!!", "ash@pokemon.com:master0", "wozMan@free.com:apple1", "pescobar@coca.com:thuglife", "lisa@app13.com:stev0j0bs", "chewy@cool.com:things", "ccups@reisfun.net:h20isgood", "solo@starwars.com:reds0lo", "dacoach@bears.com:shuffle", "pack3rh4ter@bears.com:th3ysuck", "bill@wind0z.ru:h4cker1", "mario@nintendo.jp:i<3princess", "donkey@k0n.go:barre11$", "dritchie@bell.com:c4lif3!"};
```

If we press the button get cups, this will give us an **string**.
More below, we have the method **a(char[] cArr)**
```java
public char[] a(char[] cArr) {  
        int[] iArr = {453, 431, 409, 342, 318, 293, 460, 273, 383, 369, 374, 466, 261, 380, 513, 267, 301, 266, 310, 437, 260, 325, 379, 333, 454, 350, 345, 460, 293, 303, 289, 290, 438, 373, 264, 309, 351};  
        char[] cArr2 = new char[iArr.length];  
        int length = iArr.length;  
        int length2 = cArr.length;  
        int i = 0;  
        for (int i2 = 0; i2 < length; i2++) {  
            int i3 = ((iArr[i2] - 2) ^ ((cArr[i] - 19) + 86)) >> 2;  
            i++;  
            if (i == length2 || cArr[i] == 0) {  
                i = 0;  
            }  
            cArr2[i2] = (char) i3;  
        }  
        return cArr2;  
    }
```

This method have an **obfuscation logic**.
- `iArr` Is the **integer array** that have some chars.
- `cArr` Is the **char array** passed as **arg**.
- The method iterates in each element of `iArr`.
- For each index (`i2`) of `iArr`, is realized an **XOR** operation.

And we have another **class** and most important, the **g** class.
We have the following **methods**
- `a(char c, char c2)`
```java
boolean a(char c, char c2) { return (c ^ c2) != 21;
```
This method take **two chars** `c` and `c2`, is **XORed** between and check if the **result isn't 21**.

- `a(char c)`
```java
boolean a(char c) {
    return ((c & 15) ^ c) != 96;
}
```
This method take **one char**, make an **AND** operation **between `c` and 15** and then is **XORed** with the **result** and **c**. Check if the **result isn't 96**.

- `b(char c)`
```java
int b(char c) {
    return (c - 5) ^ 3;
}
```
This method take **one char** `c` and subtract **5**, then is **XORed** with **3**. Return the **result** of the operation.

- `c(char c)`
```java
int c(char c) {
    return c * '\"';
}
```
This method take the **c** char and is multipled by **34**.

- `d(char c)`
```java
boolean d(char c) {
    return ((c & 15) == 4 && (c & 240) == 96) ? false : true;
}
```
This method take **one char** `c` and make **two AND**.
The **first one** with **15** (for obtain **4 bits** less significant) and **check if result is 4**.
The **second** with **240** (for obtain **4 bits** more significant) and **check if result is 96**.

And
- `a(String str, char c)`
Use the **previous methods** for **verify** each char of the **password**. And then, **build an char array**.

So, here's a **python** script that make the **brute force** process.
```python
def decrypt(key):
    enc = [453, 431, 409, 342, 318, 293, 460, 273, 383, 369, 374, 466,
           261, 380, 513, 267, 301, 266, 310, 437, 260, 325, 379, 333,
           454, 350, 345, 460, 293, 303, 289, 290, 438, 373, 264, 309, 351]

    out = ""
    for i in range(len(enc)):
        cur = enc[i] - 2
        k = ord(key[i % len(key)]) + (86 - 19)  # 86 - 19 = 67
        cur ^= k
        cur >>= 2

        if cur > 255:
            return False
        out += chr(cur)

    return out

def brute_force():
    for c0 in range(32, 127):
        for c5 in range(32, 127):
            if (c0 ^ c5) != 21:  # a(char c, char c2) -> == 21
                continue
            for c1 in range(32, 127):
                if (c1 ^ (c1 & 15)) != 96:  # a(char c) -> == 96
                    continue
                for c2 in range(32, 127):
                    if (c2 - 5) ^ 3 != 115:  # b(char c) ->  == 115
                        continue
                    for c3 in range(32, 127):
                        if c3 * 34 != 3570:  # c(char c) -> == 3570
                            continue
                        c4 = 100  # (d(char c) -> == 100)
                        for email4 in range(32, 127):  # 4th char of email
                            key = chr(email4) + chr(c0) + chr(c1) + chr(c2) + chr(c3) + chr(c4) + chr(c5)
                            res = decrypt(key)
                            if res and "PAN" in res:  # Searc for PAN (Flag format)
                                print(f"Flag: {res} ({key})")

brute_force()
```

And here's the **four corrects flags**
![[laby2016_cups2.png]]

Flags
**`PAN{da_cups_is_halfEmpty_||_halfFull} (=fluids)`**
**`PAN{da_cups_is_halfEmpty_||_halfFull} (>fluids)`**
**`PAN{da_cups_is_halfEmpty_||_halfFull} (?fluids)`**
**`PAN{da_cups_is_halfEmpty_||_halfFull} (@fluids)`**

I hope you found it useful (: