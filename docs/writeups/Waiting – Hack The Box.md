![[waiting1.png]]
**Difficult:** Medium
**Category**: Mobile
**OS**: Android

**Description**: The app stores a secret and says it is stored securely even in case the application has been tampered. Are you able to retrieve it?

---

As always, download the **.zip** file and extrat with **hackthebox** as **password**.

Decompile with **apktool**
```bash
apktool d app-release.apk
```
The **SDK** is **31**, then we can use our **Android 12 (SDK API 31)** of Genymotion.

Now, install the **apk** with **adb**.
![[waiting2.png]]

![[waiting3.png]]

If you **press the button** again, you **will get a new token**. With the **same data**.
Let’s inspect the **source code** with **jadx**.
I can find this code in **com.example.waiting.Secrets**
```java
package com.example.waiting;

/* loaded from: classes.dex */
public final class Secrets {

    /* renamed from: a, reason: collision with root package name */
    public static final a f1031a = new a(null);

    /* loaded from: classes.dex */
    public static final class a {
        private a() {
        }

        public /* synthetic */ a(a.a.a.a aVar) {
            this();
        }
    }

    static {
        System.loadLibrary("secrets");
    }

    public final native String getdxXEPMNe();
}
```

Then, it’s a library. We need know what are in the **apk** file
![[waiting4.png]]

We have **libnative-lib.so** and **libsecrets.so**
Probably we want inspect **libresecrets**.
Then, let’s open **ghidra** and the **file**.

We have the **Java_com_example_waiting_Secrets_getdxXEPMNe** function
```c
__int64 __fastcall Java_com_example_waiting_Secrets_getdxXEPMNe(__int64 a1, __int64 a2, __int64 a3)
{
  const char *v4; // x0
  unsigned __int64 i; // x23
  char v6; // w26
  unsigned __int64 v7; // x0
  _BYTE v9[52]; // [xsp+0h] [xbp-C0h] BYREF
  char v10[68]; // [xsp+34h] [xbp-8Ch] BYREF
  __int64 v11; // [xsp+78h] [xbp-48h]

  v11 = *(_QWORD *)(_ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2)) + 40);
  v4 = (const char *)(*(__int64 (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)a1 + 1352LL))(a1, a3, 0LL);
  sha256(v4, v10);
  for ( i = 0LL; i != 48; ++i )
  {
    v6 = byte_13B5[i];
    v7 = __strlen_chk(v10, 0x41u);
    v9[i] = v10[i - i / v7 * v7] ^ v6;
  }
  v9[48] = 0;
  return (*(__int64 (__fastcall **)(__int64, _BYTE *))(*(_QWORD *)a1 + 1336LL))(a1, v9);
}
```

There are an **SHA256 encrypt** (**v4**) and is stored in **v10**.
Then, is **XORed** with **byte_13B5**
The **value of sha256** is **com.example.waiting**
Just we need “**crack**” it, I don’t know if this is the **intended path**, but this challenge Is so weird.
I spend so much time with the **fields** 

You can use this **python** script
```python
# Import the hashlib library to use the sha256 hash function
from hashlib import sha256

# Define a lambda function for printing information with a prefix
print_info = lambda x: print(f"[+] {x}")

# Define a list of bytes used for decryption
byte_array = [0x71, 0x67, 0x23, 0x4A, 0x23, 0x8, 0x1, 0x1, 0x67, 0x5, 0x41, 0x41, 0x3, 0x5B, 0x51, 0x3A, 0x51, 0x5E, 0x17, 0x5C, 0x6A, 0x4D, 0x52, 0x9, 0x48, 0x57, 0x14, 0x5, 0x5A, 0x5F, 0x6A, 0x5, 0xC, 0x6, 0x5, 0xD, 0x50, 0x69, 0x5, 0x54, 0x55, 0x58, 0x51, 0x7, 0xE, 0x4B, 0x10, 0x18]

# Define the name of the application
app_name = 'com.example.waiting'

# Initialize an empty string to store the decrypted flag
flag =''

# Check if the script is being run as the main program
if __name__ == '__main__':
    # Calculate the SHA256 hash of the application name and convert it to hexadecimal
    sha256_hash = sha256(app_name.encode()).hexdigest()

    # Decrypt the SHA256 hash using XOR with the byte array
    for i in range(len(byte_array)):
        flag += chr(ord(sha256_hash[i]) ^ byte_array[i])

    # Print the decrypted flag
    print_info(f"{flag}")
```
I was need **FriendGPT** for this script, because I lost the motivation with this challenge

I hope you found it useful (: