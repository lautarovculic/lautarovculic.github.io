#ctf #dart #flutter #rev-libraries #blutter #crypto 
**Description**: Introducing DroidPass - the "secure" password manager that promises military-grade encryption for all your sensitive credentials!

**Link**: https://academy.8ksec.io/course/android-application-exploitation-challenges

![[8ksec-DroidPass_1.png]]

Install the `.apk` file using **ADB**.
```bash
adb install -r DroidPass.apk
```

When using the app, **we realize that its features are limited and that it fulfills the classic role of a password generator with different generation options**.
The objective of this challenge is *not to crack passwords, keys, or initialization vectors*.
Also not is it to extract SQLite databases from the device, but simply to **understand how it works by applying reverse engineering**.

Let's inspect the **source code** using **JADX**.
We quickly noticed that the **app is built in Flutter** and **has a couple of security checks**.

We can see in the `SecurityModule` class that it loads the `libsecurity-checks.so`library.
This class **checks whether the device is rooted, whether it is an emulator, or whether it is being dynamically manipulated using debugging tools**.

In any case, *we will not concern ourselves with this because it is outside the scope of our objective*, which is **static analysis.**
After searching (unsuccessfully) for information in the code we see in *JADX*, **we will probably have to look at the `.so` libraries**.

Let's decompile the `.apk` file using **apktool**
```bash
apktool d DroidPass.apk
```

Then:
```bash
tree DroidPass/lib/x86_64
```
We can see the libraries
```bash
.
├── libapp.so
├── libc++_shared.so
├── libflutter.so
└── libsecurity-checks.so
```

We just will **focus** in `libapp.so` file.
Normally, we would use **ghidra**, **radare2**, or *IDA for binary analysis*.

The code is in **Dart bytecode** inside `libapp.so`, not in traditional ARM functions.
That's why these tools see “*stubs*” and *data*, but **don't interpret the VM or reconstruct the Dart logic**, so they *don't show the actual code flow either*.

In any case, we can use *radare2 to find a little more information*, search for texts, and get ideas so that we can later figure out *how to tackle the challenge and have as much information as possible*.
```bash
r2 -AA -e bin.relocs.apply=true libapp.so
```
We will look for some interesting chains.
And, after some minutes trying randoms keywords, i noticed that:
```bash
[0x00200000]> iz~_hardcodedKey
4808  0x0002a39c 0x0002a39c 27  28   .rodata ascii   set:_hardcodedKey@477197192
12031 0x0005c2c1 0x0005c2c1 23  24   .rodata ascii   _hardcodedKey@477197192
```

At this point, I got serious and decided to use the **blutter** tool.
Repo: https://github.com/worawit/blutter
What does this tool do?
- It *extracts and decompiles the Dart snapshot/bytecode embedded* within a Flutter binary (`libapp.so`).
- Converts those sections (`.rodata` with `kernel_blob.bin`) into *readable Dart pseudo-code, so you can see functions, strings, and logic that are not normally visible with ghidra/r2*.
- Allows you to *reconstruct classes, methods, and constants* (such as hardcoded keys) statically.

Install blutter and then:
```bash
python3 blutter.py /DroidPass/lib/x86_64 out_droidpass_x86_64
```

```bash
tree -L 1 out_droidpass
```
Content:
```bash
out_droidpass
├── asm // contains disassembled ARM/Thumb code
├── blutter_frida.js // optional script to dump live Dart objects via Frida
├── ida_script // helper scripts for IDA
├── objs.txt // raw dump of all Dart VM objects (classes, fields, closures)
└── pp.txt // pretty-printed version of `objs.txt`
```

At what point in execution are *keys normally used*?
When we *encrypt something*.
This app, *what does it want to encrypt*?
*Passwords*
Where are they **stored** and with **what tool**?
*SQLite* (`.db`)

Then we would only need to **search for features related to databases**.
But, where? We have many directories and files `.dart`.
```bash
tree out_droidpass/asm/droid_pass
```
Output:
```bash
out_droidpass/asm/droid_pass
├── main.dart
├── models
│   └── password.dart
└── services
    ├── database_helper.dart
    ├── encryption_service.dart
    ├── password_generator.dart
    └── security_service.dart
```
Here is the *main code that the application developer has implemented*. So we can **load the directory as a folder in Visual Studio Code**. And then, search for *useful login implementations*.

In `main.dart`, we can see the functions that the application has, including the function `_savePassword()`.
```assembly
_ _savePassword(/* No info */) async {
// ** addr: 0x391ff4, size: 0x29c
// 0x391ff4: EnterFrame
// 0x391ff4: stp fp, lr, [SP, #-0x10]!
// 0x391ff8: mov fp, SP
// 0x391ffc: AllocStack(0xa8)
// 0x391ffc: sub SP, SP, #0xa8
// 0x392000: SetupParameters(_PasswordHomePageState this /* r1 => r1, fp-0x78 */)
// 0x392000: stur NULL, [fp, #-8]
// 0x392004: stur x1, [fp, #-0x78]
// 0x392008: CheckStackOverflow
// 0x392008: ldr x16, [THR, #0x38] ; THR::stack_limit
// 0x39200c: cmp SP, x16
// 0x392010: b.ls #0x392284
// 0x392014: r1 = 1
```
But apparently, the code we are interested in is in another `.dart` file.

```bash
grep -Rni "_hardcodedKey@477197192" .
```
Output:
```bash
./services/encryption_service.dart:438:    // 0x2859d0: r16 = "_hardcodedKey@477197192"
./services/encryption_service.dart:439:    //     0x2859d0: add             x16, PP, #0xe, lsl #12  ; [pp+0xe908] "_hardcodedKey@477197192"
```

Let's take a look more closer to **`/services/encryption_service.dart`** file.
Specifically, the class constructor, `_ EncryptionService`, is **where the Key and IV are initialized**.
The process for *generating the key is quite convoluted, a clear obfuscation technique to hide it*.

- **Creating a Array of Integers**
The first step the app takes is *to create a list of integers* (which are actually *bytes*). This is clearly visible in the code starting at address `0x28571c`.
```assembly
0x28571c: bl #0x540088 ; AllocateArrayStub
```

Then, it **starts to fill up with hexadecimal values**.
```assembly
[...]
[...]
0x285724: mov x16, #0x82
0x285728: StoreField: r0->field_f = r16
0x285728: stur w16, [x0, #0xf]
0x28572c: r16 = 228
0x28572c: mov x16, #0xe4
0x285730: StoreField: r0->field_13 = r16
0x285730: stur w16, [x0, #0x13]
0x285734: r16 = 186
0x285734: mov x16, #0xba
0x285738: ArrayStore: r0[0] = r16 ; List_4
0x285738: stur w16, [x0, #0x17]
0x28573c: r16 = 206
0x28573c: mov x16, #0xce
0x285740: StoreField: r0->field_1b = r16
0x285740: stur w16, [x0, #0x1b]
0x285744: r16 = 200
0x285744: mov x16, #0xc8
0x285748: StoreField: r0->field_1f = r16
0x285748: stur w16, [x0, #0x1f]
0x28574c: r16 = 190
[...]
[...]
[...]
[...]
```

The application hardcodes a *list of bytes in an obfuscated form, loading each value individually into a register and then storing it in memory*. If we extract all those hexadecimal values, we get the *initial list of 54 integers*:
```assembly
0x2856ec: r0 = 54
0x2856ec: mov x0, #0x36
```

Integer values being stored in array:
```assembly
r16 = 130    // 0x82
r16 = 228    // 0xe4  
r16 = 186    // 0xba
r16 = 206    // 0xce
r16 = 200    // 0xc8
r16 = 190    // 0xbe
r16 = 194    // 0xc2
r16 = 130    // 0x82
r16 = 130    // 0x82
r16 = 162    // 0xa2
r16 = 170    // 0xaa
r16 = 224    // 0xe0
r16 = 202    // 0xca
r16 = 228    // 0xe4
r16 = 162    // 0xa2
r16 = 202    // 0xca
r16 = 198    // 0xc6
r16 = 228    // 0xe4
r16 = 202    // 0xca
r16 = 232    // 0xe8
r16 = 150    // 0x96
r16 = 202    // 0xca
r16 = 242    // 0xf2
r16 = 106    // 0x6a
r16 = 100    // 0x64
r16 = 102    // 0x66
r16 = 66     // 0x42
```

- **Manipulating the Array to create a String**
The application *does not use that list directly*. It cuts it **into parts**, **reverses the order of those parts**, and **converts them to characters to create a string**. This process is *repeated several times and concatenated to form a final string that I call `hardcodedKey`*.

Looking this sequence:
1. Take a sublist
```assembly
0x285830: r0 = sublist()
0x285830: bl #0x2d6fac ; [dart:core] _GrowableList::sublist
```
2. Reverse the sublist
```assembly
0x285840: r0 = ReversedListIterable()
0x285840: bl              #0x2ad5f4 ; AllocateReversedListIterableStub 
```
3. Convert bytes (int) to characters
```assembly
0x285858: r0 = createFromCharCodes()
0x285858: bl #0x22080c ; [dart:core] _StringBase::createFromCharCodes
```

- **Creates an array of 54 integers** with the values shown above
- **Splits the array into three parts:**
    - First 18 elements (indices 0-17)
    - Middle 18 elements (indices 18-35)
    - Last 18 elements (indices 36-53)
- **Reverses each part and converts to strings:**
    - Takes first 18, reverses them, converts to chars: `createFromCharCodes()`
    - Takes middle 18, converts to chars directly
    - Takes last 18, reverses them, converts to chars: `createFromCharCodes()`
- **Concatenates the three parts** to form the final key string

I hope you found it useful (: