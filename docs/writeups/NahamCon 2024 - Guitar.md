**Description**: Have you ever wanted to play the guitar on your phone? Here's a free app, with all guitar strings included for free!

**Download**: https://lautarovculic.com/my_files/guitar.apk

![[nahamCon2024_guitar1.png]]

Install the **APK** with **ADB**
```bash
adb install -r guitar.apk
```

As the description say, probably the flag are **hardcoded** in the **`strings.xml`** resources.
To make the writeup not so short, let's make an **explanation** about the `strings.xml` resources.

Android resources are **files used to store static app data**, such as *text*, *images*, *colors* or *layouts*, in an organized manner **outside the source code**.

For example, `strings.xml` contains **strings used in the interface**, facilitating localization (*translation*) and *maintenance*. They are accessed with `R.string.string_name`.

```XML
<resources>
    <string name="app_name">MiApp</string>
</resources>
```

Knowing this, **we can search by the word “flag”**.
Let's *decompile the apk* with **apktool**
```bash
apktool d guitar.apk
```

Then, go to the *new directory* and search in `guitar/res/values/strings.xml`
We can found this line in XML code
`<string name="secret_string">VGhlIGZsYWcgaXM6IGZsYWd7NDZhZmQ0ZjhkMmNhNTk1YzA5ZTRhYTI5N2I4NGFjYzF9Lg==</string>`
Which, is a *simple base64* encode.

Flag: **`flag{46afd4f8d2ca595c09e4aa297b84acc1}`**

I hope you found it useful (: