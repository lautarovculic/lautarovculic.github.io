**Description**: None of the free note taking app offer encryption... So I made my own!

**Download**: https://lautarovculic.com/my_files/secure_notes.apk

![[nahamcon2022_securenotes1.png]]

Install the **APK** file with **ADB**
```bash
adb install -r secure_notes.apk
```

We can see that we need insert a **4-Digit PIN**.
If we insert any number, we get the *Wrong password* message.

Let's inspect the **source code** using **jadx**.
The *package name* is `com.congon4tor.securenotes`.

We have **two activities** in *`AndroidManifest.xml`* file:
- `LoginActivity` -> MainActivity also?¿?¿ -> PIN Screen
- `MainActivity` -> Just the "Menu screen app".

```XML
<activity
    android:name="com.congon4tor.securenotes.LoginActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
<activity
    android:name="com.congon4tor.securenotes.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
```

*This is controversial, and I don't know if it is intentional.*
*Because we have two activities that have the category of LAUNCHER. This can cause problems when running the application in recent versions of Android, because both activities will appear in the “Home” of the device.*

This behavior *officially not supported but allowed*, and in *certain versions of Android* (depending on the launcher) it can:
- Show *two separate app icons*.
- Break the normal launcher **flow**.
- Generate conflicts with `taskAffinity`, `backstack` or *intent routing*.
- In *older launchers it directly causes an activity to never appear*.

If you have problems starting the application, you can use the following **ADB command**:
```bash
adb shell am start -n com.congon4tor.securenotes/com.congon4tor.securenotes.LoginActivity
```

Let's continue with the challenge.
After search in `strings.xml` file, I didn't find nothing.

So, it's time for *java code*.
Starting as probably the flow is, let's start with **`LoginActivity`** code.

Here's a **declaration of variables**:
```java
public ViewOnClickListenerC0320a(TextView textView, File file, Intent intent) {
    this.f2153b = textView;
    this.f2154c = file;
    this.f2155d = intent;
}
```

The *`textView`* is the **PIN** input.

We have the `onClick()` method:
```java
public void onClick(View view) {
    try {
        C0590d.m2126k(this.f2153b.getText().toString() + this.f2153b.getText().toString() + this.f2153b.getText().toString() + this.f2153b.getText().toString(), new File(this.f2154c.getPath()), new File(LoginActivity.this.getCacheDir(), "notes.db"));
        LoginActivity.this.startActivity(this.f2155d);
    } catch (C0596a unused) {
        Toast.makeText(LoginActivity.this.getApplicationContext(), "Wrong password", 0).show();
    }
}
```
Where will try put the **same PIN** four **times** for **decrypt** the **`notes.db`** file.
So, the **AES** key is **`PINPINPINPIN`**.

Also we have
```java
Intent intent = new Intent(this, (Class<?>) MainActivity.class);
File file = new File(getCacheDir() + "/db.encrypted");
if (!file.exists()) {
    try {
        InputStream open = getAssets().open("databases/db.encrypted");
        byte[] bArr = new byte[open.available()];
        open.read(bArr);
        open.close();
        FileOutputStream fileOutputStream = new FileOutputStream(file);
        fileOutputStream.write(bArr);
        fileOutputStream.close();
    } catch (Exception e2) {
        throw new RuntimeException(e2);
    }
}
```
The `db.encrypted` file that will try to **decrypt** for **get the notes**.

The file can *be pulled* from device but if you have a **non-rooted** device, then just *decompile* the **APK** with `apktool`
```bash
apktool d secure_notes.apk
```

Inside of `/assets/databases` directory you will find the `db.encrypted` file.
Notice that in my case, the **class** where the **decrypt** take place, is **`C0590d`**.
```java
public static void m2126k(String str, File file, File file2) {
    try {
        SecretKeySpec secretKeySpec = new SecretKeySpec(str.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(2, secretKeySpec);
        FileInputStream fileInputStream = new FileInputStream(file);
        byte[] bArr = new byte[(int) file.length()];
        fileInputStream.read(bArr);
        byte[] doFinal = cipher.doFinal(bArr);
        FileOutputStream fileOutputStream = new FileOutputStream(file2);
        fileOutputStream.write(doFinal);
        fileInputStream.close();
        fileOutputStream.close();
    } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e2) {
        throw new C0596a("Error encrypting/decrypting file", e2);
    }
}
```

The `notes.db` is formatted in **`JSON`** (See `MainActivity`)
```java
try {
    JSONArray jSONArray = new JSONObject(stringBuffer.toString()).getJSONArray("notes");
    for (int i3 = 0; i3 < jSONArray.length(); i3++) {
        JSONObject jSONObject = jSONArray.getJSONObject(i3);
        arrayList.add(new C0614b(jSONObject.getInt("id"), jSONObject.getString("name"), jSONObject.getString("content")));
    }
}
```

We just need **brute-force** the **PIN**. And then, *extract the `notes.db`* file.
Here's a *python* script that do the work:
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import json

def try_decrypt(key_str, input_path="db.encrypted"):
    key_bytes = key_str.encode('utf-8')
    cipher = AES.new(key_bytes, AES.MODE_ECB)

    with open(input_path, "rb") as f:
        encrypted = f.read()

    try:
        decrypted = cipher.decrypt(encrypted)
        decrypted = unpad(decrypted, AES.block_size)  # PKCS5/7 padding
        decoded = decrypted.decode('utf-8')
        obj = json.loads(decoded)
        return obj
    except Exception as e:
        return None

for i in range(10000):
    pin = str(i).zfill(4)
    key_str = pin * 4  # same app logic
    result = try_decrypt(key_str)
    if result and "notes" in result:
        print(f"[+] PIN: {pin}")
        with open("notes.db", "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        break
else:
    print("[-] No valid PIN.")
```

Then, *cat* the `notes.db` and get the flag!

![[nahamcon2022_securenotes2.png]]

Flag: **`flag{a5f6f2f861cb52b98ebedcc7c7094354}`**

I hope you found it useful (: