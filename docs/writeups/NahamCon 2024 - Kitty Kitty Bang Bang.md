---
title: NahamCon 2024 - Kitty Kitty Bang Bang
description: "I found a cool android app to play with a cowboy cat! There's has to be more going on with the app I can't see on my screen..."
tags:
  - logs
  - logcat
  - NahamCon
  - android
keywords:
  - android reversing
  - ctf writeup
  - NahamCon
  - mobile writeups
  - apk decompilation
  - frida tool
  - mobile security research
canonical: https://lautarovculic.github.io/writeups/NahamCon%202024%20-%20Kitty%20Kitty%20Bang%20Bang/
---

**Description**: I found a cool android app to play with a cowboy cat! There's has to be more going on with the app I can't see on my screen...

**Download**: https://lautarovculic.com/my_files/kittykittybangbang.apk

![[nahamCon2024_kitty1.png]]

Install the **APK** with **ADB**
```bash
adb install -r kittykittybangbang.apk
```

Let's decompile it with **apktool**
```bash
apktool d kittykittybangbang.apk
```
Also, we can **inspect the source code** with **jadx** (GUI version)

We can see in the **MainActivity** class the following java code
```java
public static final boolean onCreate$lambda$0(MainActivity this$0, View view, MotionEvent motionEvent) {
    Intrinsics.checkNotNullParameter(this$0, "this$0");
    Log.i("kitty kitty bang bang", "Listening for taps...");
    
    if (motionEvent.getAction() != 0) {
        return true;
    }
    
    Log.i("kitty kitty bang bang", "Screen tapped!");
    this$0.showOverlayImage();
    this$0.playSound(R.raw.bang);
    Log.i("kitty kitty bang bang", "BANG!");
    Log.i("kitty kitty bang bang", "flag{" + this$0.stringFromJNI() + '}');
    
    return true;
}
```

After a scare (I had the volume too loud) I noticed that the application **reacts after a screen tap**.

And that's why app's called Kitty and there's a cat...

![[nahamCon2024_kitty2.png]]

Just run **logcat** grepping *flag* string
```bash
adb logcat | grep flag{
```

Flag: **`flag{f9028245dd46eedbf9b4f8861d73ae0f}`**

I hope you found it useful (: