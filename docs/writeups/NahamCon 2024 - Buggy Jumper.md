**Description**: Buggy Jumper is a new mobile game that can be enjoyable for both gamers and hackers! There's a lot going on, can you get some of game's source code to see whats happening behind the scenes?

**Download**: https://lautarovculic.com/my_files/buggyjumper.apk

![[nahamCon2024_bjump1.png]]

Install the **APK** with **ADB**
```bash
adb install -r buggyjumper.apk
```

Let's decompile it with **apktool**
```bash
apktool d buggyjumper.apk
```

The app has been developed in **Godot Engine**. So, we can use this tool
https://github.com/GDRETools/gdsdecomp

When you have the tool installed, *just launch it*.
We can see in the *directory that apktool has drop to us* this directory
`/buggyjumper/assets/scripts`
Inside:
```bash
.
├── flag.gdc
├── flag.gd.remap
├── MainScene.gdc
├── MainScene.gd.remap
├── shop.gdc
└── shop.gd.remap
```

Let's check the file `flag.gdc` with the `gdre_tools`.
![[nahamCon2024_bjump2.png]]
Then, now just `strings flag.gd` and we get the flag.

Flag: **`flag{c2d5a0c9cae9857a3cfa662cd2869835}`**

I hope you found it useful (: