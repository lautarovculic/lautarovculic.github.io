**Description**: I created a cookie clicker application to pass the time. There's a special prize that I can't seem to get.

**Download**: https://lautarovculic.com/my_files/click_me.apk

![[nahamCon_2022-ClickMe1.png]]

Install the **apk** with **ADB**
```bash
adb install -r click_me.apk
```

*Decompile it* with **apktool**
```bash
apktool d click_me.apk
```

Then, let's open the **apk** with **jadx** (GUI version) for check **source code**.
The **package name** is `com.example.clickme`. We have the **MainActivity**, and another class called **ActivityMainBinding**. But we'll work with the first one.

We have the *main logic* here:
```java
public final void getFlagButtonClick(View view) {
    Intrinsics.checkNotNullParameter(view, "view");
    if (this.CLICKS == 99999999) {
        Toast.makeText(getApplicationContext(), getFlag(), 0).show();
    } else {
        Toast.makeText(getApplicationContext(), "You do not have enough cookies to get the flag", 0).show();
    }
}
```

Mmmm... This may be really simple, we just need change `99999999`by `0` haha.
So, come to `smali` directory that **apktool** has drop to us.
```bash
tree click_me/smali/com/example/clickme/
click_me/smali/com/example/clickme/
├── BuildConfig.smali
├── databinding
│   └── ActivityMainBinding.smali
├── MainActivity$Companion.smali
├── MainActivity.smali
├── R$color.smali
├── R$drawable.smali
├── R$id.smali
├── R$layout.smali
├── R$mipmap.smali
├── R$string.smali
├── R$style.smali
└── R.smali
```

We just need `MainActivity.smali` file.
We can found the **declaration** of *variables*.
![[nahamCon_2022-ClickMe2.png]]

The `0x5f5e0ff` number is `99999999`.
And `0x0` is `0`.

We just need change `0x5f5e0ff` by `0x0`.
Then, the logic in *java code* must look like:
```java
if (this.CLICKS == 0) {
        Toast.makeText(getApplicationContext(), getFlag(), 0).show();
    }
```

Save the `.smali` file. And it's *rebuild time*!

Come to our directory path where we have the *original apk*.
Then
```bash
apktool b click_me
```

This will create a *new apk* (patched) in `click_me/dist/click_me.apk`
Let's **align** the `.apk` with **zipalign**
```bash
zipalign -v -p 4 click_me/dist/click_me.apk clicc_me-aligned.apk
```

Now, let's create a **key** with **keytool**
```bash
keytool -genkey -v -keystore name.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias alias
```

And then, **sign** the *aligned* apk with **apksigner**
```bash
apksigner sign --ks name.keystore --ks-key-alias alias --ks-pass pass:lautaro --key-pass pass:lautaro --out click_me-signed.apk click_me-aligned.apk
```

Let's **uninstall** the original app in our device, then, install the *new signed apk* with **ADB**
```bash
adb install -r click_me-signed.apk
```

Run the app, then, **GET THE FLAG**!

Flag: **`flag{849d9e5421c59358ee4d568adebc5a70}`**

I hope you found it useful (: