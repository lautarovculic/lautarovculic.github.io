![[apkey1.png]]
**Difficult:** Easy
**Category**: Mobile
**OS**: Android (SDK 30)

**Description**: This app contains some unique keys. Can you get one?

---

First, we need download the **.apk**
For this mobile challenge,we need install an Android device with SDK 30 (Android 11 máx) with Genymotion.

Decompile the **.apk** with **apktool**
```bash
apktool d APKey.apk
```

![[apkey2.png]]

Here we can see that is a **simple login**, so, probably we need bypass that.
We can use the **jadx** tool for making the work.

Looking around the source code I found this:
![[apkey3.png]]

There are the condition in the login. If the **username = admin** and the **password = MD5** (`a2a3d412e92d896134d9c9126d756f`) the app will trigger a Toast message at the end of the screen.
Let’s inspect inside of this situation.

Looking for **smali** files, I noticed that jadx is a bad choice. So I inspect for myself the file that is located in:
```bash
/APKey/smali/com/example/apkey/MainActivity$a.smali
```
But, why I’m looking for **smali** files?

Smali files are the **assembly code representation** of the **source code** of an Android application. When you _compile an Android application_, the Java source code _is converted to **Dalvik** code_, which can then **be disassembled to Smali**. Analyzing Smali files can help to understand the inner workings of the application at the low-level code level.
![[apkey4.png]]

Anyways, I will write a post about Dalvik code in the further explaining in deep this amazing topic.
For the moment, let’s inspect the **MainActivity$a.smali** file with code

In the **37 line start the public method onClick**
![[apkey5.png]]

The selected code in the source code is represented at this point:
![[apkey6.png]]

Then, we need work with the second “**if-eqz**” condition that is in the **148 line**
![[apkey7.png]]

Source code represent:
![[apkey8.png]]
So we have **if-eqz p1, :cond_1**

**Example**
p1 = 1 + 1
### if-eqz = p1 = 2, :then (flag) (but we don’t know the passwd)

We need change the function to **if-nez**
### if-nez = p1 = 3, :then (flag) (just if we type the correct passwd will get the ‘Wrong Credentials’ Toast msg)
So, changing the expected value to any random, **if we type the incorrect password**, the flag will jump because **not match**.

Then, change the **eqz** to **nez**
![[apkey9.png]]

Save the file and **rebuild** with **apktool** the apk.
![[apkey10.png]]

```bash
apktool b APKey
```
![[apkey11.png]]

Now it’s time for create a keystore for sign the apk:
```bash
keytool -genkeypair -v -keystore mykey.jks -keyalg RSA -keysize 2048 -validity 3650 -alias myalias
```

Now with the keystore, we can use **apksigner** for the _signing_:
```bash
apksigner sign --ks mykey.jks --ks-key-alias myalias --out apk.apk APKey/dist/APKey.apk
```

![[apkey12.png]]

Now we can reinstall the apk with adb, run this command:
```bash
adb install -r apk.apk
```
But previously we need uninstall the APKey.apk original file.

Then:
![[apkey13.png]]

I hope you found it useful (: