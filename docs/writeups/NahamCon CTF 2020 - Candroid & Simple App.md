## Candroid
**Description**: I think I can, I think I can!
**Download**: https://lautarovculic.com/my_files/candroid.apk

![[nahamcon2020_candroid1.png]]

Install the **APK** file with **ADB**
```bash
adb install -r candroid.apk
```

Decompile the application with **apktool**
```bash
apktool d candroid.apk
```

The app name is "*Nahamcon1*"
If we insert any text as password, a message will prompt saying:
`Error: Reading the password file`

Notice that a `password.txt` file is created in the **external directory**:
```java
File file = new File(Environment.getExternalStorageDirectory(), "password.txt");
```

But looking in the directory I can't find the `password.txt` even giving storage permissions.
```bash
ginkgo:/storage/emulated/0 $ ls -la
total 51
drwxrwx--- 2 root everybody 3488 2022-02-16 12:04 Alarms
drwxrwx--- 5 root everybody 3488 2024-12-31 05:38 Android
drwxrwx--- 2 root everybody 3488 2022-02-16 12:04 Audiobooks
drwxrwx--- 5 root everybody 3488 2024-10-06 18:20 DCIM
drwxrwx--- 2 root everybody 3488 2025-02-23 23:51 Documents
drwxrwx--- 3 root everybody 3488 2025-04-04 19:18 Download
drwxrwx--- 5 root everybody 3488 2025-03-05 07:56 MIUI
drwxrwx--- 3 root everybody 3488 2022-02-16 12:04 Movies
drwxrwx--- 3 root everybody 3488 2024-12-31 03:34 Music
drwxrwx--- 2 root everybody 3488 2022-02-16 12:04 Notifications
drwxrwx--- 4 root everybody 3488 2024-12-31 03:36 Pictures
drwxrwx--- 2 root everybody 3488 2022-02-16 12:04 Ringtones
drwxrwx--- 2 root everybody 3488 2023-02-02 18:42 TWRP
drwxrwx--- 3 root everybody 3488 2024-07-22 06:54 com.xiaomi.bluetooth
drwxrwx--- 2 root everybody 3488 2024-12-31 05:54 mylib
drwxrwx--- 2 root everybody 3488 2025-03-29 20:33 ramdump
drwxrwx--- 3 root everybody 3488 2023-02-03 18:32 t-ui
ginkgo:/storage/emulated/0 $
```

But anyway, we can find the flag in the **resources directory** in **APK** file as **strings** values.
```bash
cat candroid/res/values/strings.xml | grep flag
```
Output:
```XML
<string name="flag">flag{4ndr0id_1s_3asy}</string>
```

Flag: **`flag{4ndr0id_1s_3asy}`**

But let's make this app vulnerable!
We just can **patch** the **APK** file.
If we *pay attention in the code line*
```java
if (editText.getText().toString().equals(MainActivity.this.checkPass.toString()) && MainActivity.this.checkPass.toString().length() != 0) {
    MainActivity.this.startActivity(new Intent(MainActivity.this, (Class<?>) FlagActivity.class));
}
```

We can see that if the **length** of the password `!= 0` as condition, the **`FlagActivity`** will be showed.
Edit the `MainActivity$1.smali` file and in the **line** `139` you will found the validation:
```smali
135     invoke-virtual {v0}, Ljava/lang/String;->length()I
136
137     move-result v0
138
139     if-eqz v0, :cond_0
```
Just change `if-eqz` to `if-nez`
Then, save the file and let's rebuild the **APK**.
Uninstall the original app from the device and follow this steps:

Rebuild the **APK** file:
```bash
apktool b candroid
```

Align the APK file
```bash
zipalign -v -p 4 candroid/dist/candroid.apk cadroid-aligned.apk
```

Then, generate a `key`
```bash
keytool -genkey -v -keystore name.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias alias
```

Sign the apk file
```bash
apksigner sign --ks name.keystore --ks-key-alias alias --ks-pass pass:lautaro --key-pass pass:lautaro --out candroid-signed.apk candroid-aligned.apk
```

And install the app again:
```bash
adb install candroid-signed.apk
```

Just press the **SUBMIT** button and then get the *flag activity*.

## Simple App
**Description**: Here's a simple Android app. Can you get the flag?
**Download**: https://lautarovculic.com/my_files/simple-app.apk

![[nahamcon2020_simpleApp1.png]]

We have a **certification error** when we try *install the apk* file.
So, as in the *previous challenge* we did, we need **align and sign** the `simple-app.apk` file.

Align:
```bash
zipalign -v -p 4 simple-app.apk simple-aligned.apk
```

Generate a key
```bash
keytool -genkey -v -keystore name.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias alias
```

Sign the app:
```bash
apksigner sign --ks name.keystore --ks-key-alias alias --ks-pass pass:lautaro --key-pass pass:lautaro --out simple-signed.apk simple-aligned.apk
```

Install the app with **ADB**
```bash
adb install simple-signed.apk
```

Now you will can launch the app without problems.
In the activity, we can see just a "**Flag checker**"

So, let's decompile the **source code** using **jadx** (we'll use the *signed version*)
In the **`MainActivity`** class, we can found the *hardcoded flag*
```java
public final class MainActivity extends AppCompatActivity {
    private HashMap _$_findViewCache;
    private final String flag = "flag{3asY_4ndr0id_r3vers1ng}";

    public void _$_clearFindViewByIdCache() {
        HashMap hashMap = this._$_findViewCache;
        if (hashMap != null) {
            hashMap.clear();
        }
    }
}
```

Flag: **`flag{3asY_4ndr0id_r3vers1ng}`**
Now we can check that in the App correctly (:
For your practice, try make it persistent!
Changing the
`"Yay that is the flag!!!" : "Nope that is not the flag."` strings by the correct flag using **patching techniques**!

I hope you found it useful (: