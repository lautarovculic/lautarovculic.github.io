**Description**: Welcome to the **iOS Application Security Lab: Jailbreak Detection Evasion Challenge**. The challenge centers around a fictitious app called No Escape, designed with robust jailbreak detection mechanisms. Your mission is to bypass these mechanisms and gain full access to the app's functionalities using Frida.

**Download**: https://lautarovculic.com/my_files/noEscape.ipa
**Link:** https://www.mobilehackinglab.com/path-player?courseid=lab-no-escape

![[noEscape1.png]]

Install an **IPA** file can be difficult.
So, for make it more easy, I made a YouTube video with the process using **Sideloadly**.
**LINK**: https://www.youtube.com/watch?v=YPpo9owRKGE

First, let's **unzip** the **`.ipa`** file.
Also, let's checks for hints in the **strings of the binary**.
```bash
strings "No Escape" | grep -iE -A10 -B10 "jailbreak|jailbroken|isJailbroken|cydia|sileo"
```

Output:
```bash
Jail broken device!
Unexpectedly found nil while unwrapping an Optional value
5i9h+}
_TtC9No_Escape14ViewController
v16@0:8
@32@0:8@16@24
messageLabel
image
T@"UITextView",N,W,VmessageLabel
T@"UIImageView",N,W,Vimage
Your device is jailbroken. This may compromise security. Quitting...
Default Configuration
No_Escape/AppDelegate.swift
Fatal error
Unresolved error
_TtC9No_Escape11AppDelegate
@16@0:8
v24@0:8@16
B32@0:8@16@24
@40@0:8@16@24@32
window
--
v40@0:8@"UIScene"16@"UISceneSession"24@"UISceneConnectionOptions"32
v24@0:8@"UIScene"16
v32@0:8@"UIScene"16@"NSSet"24
@"NSUserActivity"24@0:8@"UIScene"16
v32@0:8@"UIScene"16@"NSUserActivity"24
v32@0:8@"UIScene"16@"NSString"24
v40@0:8@"UIScene"16@"NSString"24@"NSError"32
B24@0:8@16
@32@0:8:16@24
/private/var/lib/apt/
cydia://package/com.example.package
/private/jailbreak_test.txt
This is a test.
/Applications/Cydia.app
/Library/MobileSubstrate/MobileSubstrate.dylib
/bin/bash
/usr/sbin/sshd
/etc/apt
/bin
No_Escape/GeneratedAssetSymbols.swift
_TtC9No_EscapeP33_46A0F3C550DABD6C4FDD9346E5310C1E19ResourceBundleClass
_TtC11CryptoSwiftP33_2D70F19D21807F37E375D63DC77DAAFB12BundleFinder
CryptoSwift_CryptoSwift
PACKAGE_RESOURCE_BUNDLE_PATH
```

I tried use tools like `frida` or `frida-trace` for a deep understanding of *what functions are called* but I don't get success.

![[noEscape2.png]]

Due that we don't have enough time for the process.
So we can use **radare2** and **r2frida** for *spawn and work in time* with the application.

But before, let's search for the **function**.
Open ghidra and import the binary file.

**NOTE**: Enable Decompiler Parameter ID (for an extra exercise in the future)
![[noEscape3.png]]

After a simple research, I get the **`isJailbroken` function that make the checks**
![[noEscape4.png]]

```CPP
bool No_Escape::isJailbroken(void)
{
    bool bVar1;
    dword dVar2;
    dword local_18;
    dword local_14;

    // Check for the presence of common jailbreak-related files
    dVar2 = $No_Escape.(checkForJailbreakFiles_in__BCE8F13474E5A52C60853EA803F80A81)()->_Swift.Bool();

    if ((dVar2 & 1) == 0) {
        // If no jailbreak files are found, check if system directories are writable
        local_14 = $No_Escape.(checkForWritableSystemDirectories_in__BCE8F13474E5A52C60853EA803F80A81)()->_Swift.Bool();
    } else {
        // If jailbreak files are found, immediately mark the device as jailbroken
        local_14 = 1;
    }

    if ((local_14 & 1) == 0) {
        // If system directories are not writable, check if Cydia can be opened
        local_18 = $No_Escape.(canOpenCydia_in__BCE8F13474E5A52C60853EA803F80A81)()->_Swift.Bool();
    } else {
        // If system directories are writable, mark the device as jailbroken
        local_18 = 1;
    }

    if ((local_18 & 1) == 0) {
        // If Cydia cannot be opened, check for sandbox violations
        bVar1 = $No_Escape.(checkSandboxViolation_in__BCE8F13474E5A52C60853EA803F80A81)()->_Swift.Bool();
    } else {
        // If Cydia is accessible, mark the device as jailbroken
        bVar1 = true;
    }

    // Return true if any of the checks indicate a jailbroken device
    return bVar1 != false;
}
```

That's a boolean based function, which receive the values of the another functions.
Looking, we have checks like **writeable paths**, **app stores like Cydia**, **common jailbreak files** and some sandbox checking in case that *Cydia don't open*.

So, if we just need **make all functions return 0 (`false`)**, just need a simple command in **r2frida**.
First, let's install it (with `brew`).
```bash
brew install radare2
```
And then, the plugin
```bash
r2pm -U && r2pm -i r2frida
```

Let's search for the **Bundle ID** (package name for Android lovers)
```bash
frida-ps -Uai | grep -i "escape"
```

Then now, let's **spawn** (no attach) the application.
```bash
r2 'frida://spawn/usb//com.mobilehackinglab.No-Escape.<REDACTED>'
```

Run
```bash
[0x100a64868]> :di0 `:iE~+isjailbr[0]`
[0x100a64868]> :dc
INFO: resumed spawned process
[0x100a64868]> Intercept return for 0x100a66068 with 0
Intercept return for 0x100a66068 with 0
```

This will executed in this order:
- **`:iE`** → List *all exported functions of the app*.
- **`~+isjailbr[0]`** → Filter **all functions containing the word** “`isjailbr`".
	- This uses **radare2's grep-like filtering (`~+`)** to find matches dynamically.
	- **`[0]` in `isjailbr[0]`** → *Selects the first function that matches the filter* (index `[0]`).

- **`:di0`** → *Intercepts* the selected function and modifies its return value.
The `0` in `di0` **does not refer to the index of the function**, but rather the **hook ID** used by `r2frida` to track the interception.

- **`:dc`** → *Resumes execution of the process after modifying the function return*.

And we'll bypass the **jailbreak** detection.

**But, I want patch this app (sorry MHL).**

So, the patching is simple, if you look the previous image, you can notice that the **highlighted** text in the left, are the *disassembly* code.

![[noEscape5.png]]

![[noEscape6.png]]

So, after know what **instruction** corresponds to the **binary value**, we know *where apply the patch*.
- `LAB_10000a080`
- `LAB_10000a0a4`
- `LAB_10000a0c8`
- `LAB_10000a0ec`

But, where specifically?
Well,
- `0x1` = **`True`**
- `0x0` = **`False`**

We need the **false** value in every function.
```assembly
       10000a080 20 00 80 52     mov        w0,#0x1
       10000a084 a0 c3 1f b8     stur       w0,[x29, #local_14]
       10000a088 04 00 00 14     b          LAB_10000a098
```

In the four `w0,#0x1` we need put `w0,#0x0` (in `LAB_10000a0ec` you must leave `w8`, obviously)
How to patch?
Just **right click** in the instruction that you wish patch and select
![[noEscape7.png]]

**NOTE**
The **HEX** value of **each instruction** must be **`00 00 80 52`**
The least two patches must looks like
![[noEscape8.png]]

Now we need export **as original file**
![[noEscape9.png]]

Now it's time to *replace the original binary* by our patched versions
![[noEscape10.png]]

Then, **uninstall the original app** and **install -via Sideloadly-** the new app.
![[noEscape11.png]]

After launch the app, we got the flag!
![[noEscape12.png]]

Flag: **`MHL{hidin9_in_p1@in_5i9h+}`**

I hope you found it useful (: