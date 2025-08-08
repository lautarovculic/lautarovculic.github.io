**Description**: As locks are so popular many will chase them but why? maybe a flag :)

**Download**: https://lautarovculic.com/my_files/chasingALook.apk

![[raziCTF2020_cal1.png]]

Install the **APK** with **ADB**
```bash
adb install -r chasingALook.apk
```

We can see that we need **touch** the icon **`20.000 times`**.
Let's *decompile it* with **apktool**
```bash
apktool d chasingALook.apk
```

And let's *inspect the source code* with **jadx** (GUI version).
The **package name** is `com.example.razictf_2` and there are just **one activity**, that is **`MainActivity`**. But there are some class like *a1, a2, a3, a4, a5* that probably is about **flag creation** and **switcher** class also.

Let's *understand* the `MainActivity` code.
We will *focus* in this *piece of code*
```java
public void onClick(View view) {
    TextView textView = (TextView) MainActivity.this.findViewById(R.id.Num);
    int parseInt = Integer.parseInt(textView.getText().toString());
    if (parseInt == 0 || parseInt < 0) {
        textView.setText("0");
        return;
    }
    int i = parseInt - 1;
    String run = new switcher().run(i);
    if (run != null) {
        ((TextView) MainActivity.this.findViewById(R.id.Flag)).setText(run);
    }
    textView.setText(String.valueOf(i));
}
```

We can see that in this line `int i = parseInt - 1;` *every time that we press the lock*, it's **subtracts** `1` by `1`.
We can try **subtracts** `20,000` by `20,000` :P

Let's check the *smali files*.
The **`onClick`** method I found in `MainActivity\$2.smali`.
Identifying the `- 1`, we can found in the line `72` as `add-int/lit8 v0, v0, -0x1`

But, **there are a problem**. We *cannot set `-0xE420`* (-20000 in hex) directly.
Because this opcode can **only handle values between `-128` and `127`** (because it is an **8-bit literal**). That's why you are getting errors when using `-0x4E20` (-20000), because it exceeds that range.

So, we need change `add-int/lit8 v0, v0, -0x1` by
```smali
const v1, -0x4E20
add-int v0, v0, v1
```

`const v1, -0x4E20`: **Loads** the value `-20000` (in hexadecimal: `-0x4E20`) into register `v1`.
`add-int v0, v0, v1` **Adds** the value of `v1` (`-20000`) to the **counter stored** in `v0`.

Then, it's **rebuild time**!
Let's do it in one block of code, you need run a command per time
```bash
# Build a new apk
apktool b chasingALook

# Generate a key for sign
keytool -genkey -v -keystore name.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias alias

# Align the apk
/usr/lib/jvm/java-22-openjdk/build-tools/34.0.0/zipalign -v -p 4 chasingALook/dist/chasingALook.apk chasingALook-aligned.apk

# Sign the apk
/usr/lib/jvm/java-22-openjdk/build-tools/34.0.0/apksigner sign --ks name.keystore --ks-key-alias alias --ks-pass pass:lautaro --key-pass pass:lautaro --out chasingALook-signed.apk chasingALook-aligned.apk

# Uninstall the original APK

# Install the signed apk
adb install -r chasingALook-signed.apk
```

Then, when we run the *new app*, touch just one time the *lock* and then, **get the flag**

Flag: **`RaziCTF{IN_HATE_OF_RUNNING_LOCK5}`**

I hope you found it useful (: