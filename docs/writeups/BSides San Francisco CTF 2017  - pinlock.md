**Description**: It's the developer's first mobile application. They are trying their hand at storing secrets securely. Could one of them be the flag?
**Note**: For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

Download **APK**: https://lautarovculic.com/my_files/pinstore.apk

![[bside_pinlock1.png]]

Install the **apk** with **adb**
```bash
adb install -r pinstore.apk
```

Then, **decompile with apktool**
```bash
apktool d pinstore.apk
```
Notice that we have a **simple pin code** check. Just **integers**.
Let's analyze the **source code** with **jadx**.

I notice in the **AndroidManifest.xml** file we have **two activities**
```XML
<activity android:name="pinlock.ctf.pinlock.com.pinstore.MainActivity">  
    <intent-filter>  
        <action android:name="android.intent.action.MAIN"/>  
    <category android:name="android.intent.category.LAUNCHER"/>  
    </intent-filter>  
</activity>  
<activity android:name="pinlock.ctf.pinlock.com.pinstore.SecretDisplay"/>
```

The **activity** are **exported** as `True` by default, then, we can **access** it with **adb**
```bash
adb shell am start -n pinlock.ctf.pinlock.com.pinstore/.SecretDisplay
```

![[bside_pinlock2.png]]

It's look like a **database**...
Then, we can **check** that is a **database** inside of the app if we inspect the **log** with **logcat** when we try insert a **incorrect pin**.
```bash
adb logcat -c && adb logcat

--------- beginning of main
E/AudioTrack(  660): did not receive expected priority boost on time
W/SQLiteConnectionPool( 2114): A SQLiteConnection object for database '/data/data/pinlock.ctf.pinlock.com.pinstore/databases/pinlock.db' was leaked!  Please fix your application to end transactions in progress properly and to close the database when it is no longer needed.
```

So, going inside of our **emulator** file system. And it's correct, there are a **database**.
We can download to our host machine with adb
```bash
adb pull /data/data/pinlock.ctf.pinlock.com.pinstore/databases/pinlock.db
```

Then, with **sqlite** we can see the content of the database
```bash
sqlite3 pinlock.db

SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
android_metadata  pinDB             secretsDBv1       secretsDBv2
sqlite> select * from pinDB;
1|d8531a519b3d4dfebece0259f90b466a23efc57b
sqlite> select * from secretsDBv1;
1|hcsvUnln5jMdw3GeI4o/txB5vaEf1PFAnKQ3kPsRW2o5rR0a1JE54d0BLkzXPtqB
sqlite> select * from secretsDBv2;
1|Bi528nDlNBcX9BcCC+ZqGQo1Oz01+GOWSmvxRj7jg1g=
sqlite>
```

We will use just the **first hash**
`d8531a519b3d4dfebece0259f90b466a23efc57b`
Let's crack it with **hashcat**
```bash
hashcat -m 100 hash.txt /usr/share/seclists/rockyou.txt
```

And we got the **pin**
```bash
d8531a519b3d4dfebece0259f90b466a23efc57b:7498
```

When the **SecretActivity** is started, we can see the **logs**
```bash
--------- beginning of main
D/Version ( 2114): v1
D/secret  ( 2114): hcsvUnln5jMdw3GeI4o/txB5vaEf1PFAnKQ3kPsRW2o5rR0a1JE54d0BLkzXPtqB
D/Status  ( 2114): [B@128b6e8b
```

Looking in the **folder** that **apktool** drop, in the `assets` folder we have an **README**
```text
v1.0:
- Pin database with hashed pins

v1.1:
- Added AES support for secret

v1.2:
- Derive key from pin
[To-do: switch to the new database]
```

Now is time to **read the source code of** `SecretActivity` and `CryptoUtilies`
After read, we have the string `t0ps3kr3tk3y` and this is using an algorithm to decrypt it.

We have **two secrets**
`hcsvUnln5jMdw3GeI4o/txB5vaEf1PFAnKQ3kPsRW2o5rR0a1JE54d0BLkzXPtqB`
And
`Bi528nDlNBcX9BcCC+ZqGQo1Oz01+GOWSmvxRj7jg1g=`
We need **modify** the **smali** file for switch to the **second one**.

Because we have in the **DatabaseUtilities** class
```java
public String fetchSecret() throws IOException {  
        openDB();  
        Cursor cursor = this.db.rawQuery("SELECT entry FROM secretsDBv1", null);  
        String secret = "";  
        if (cursor.moveToFirst()) {  
            secret = cursor.getString(0);  
        }  
        Log.d("secret", secret);  
        cursor.close();  
        return secret;  
    }
```
That the **rawQuery** is using `secretsDBv1` and we just change the `1` by `2`
And in the **try** if the **SecretDisplay** class, we have the `v1` string. So we need switch to `v2`
```java
try {  
            DatabaseUtilities dbUtils = new DatabaseUtilities(getApplicationContext());  
            CryptoUtilities cryptoUtils = new CryptoUtilities("v1", pin);  
            tv.setText(cryptoUtils.decrypt(dbUtils.fetchSecret()));  
        }
```

Let's find the **smali** code corresponding to this two classes.
```bash
cat DatabaseUtilities.smali | grep secretsDBv1 -n

315:    const-string v1, "SELECT entry FROM secretsDBv1"
```
In the **315** line of the code, just change `secretsDBv1` to `secretsDBv2`.
Then, save the file.

And
```bash
cat SecretDisplay.smali | grep v1 -n

74:    const-string v7, "v1"
```
In the **74** line, we have the last change that we must do. `v1` to `v2`
Save the file

And now, we just need **rebuild** the app with **apktool**
```bash
apktool b pinstore
```

Then, generate a key
```bash
keytool -genkey -v -keystore name.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias alias
```

Sign the **apk**
```bash
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore name.keystore pinstore/dist/pinstore.apk alias
```

**Delete** the original app installed and **reinstall** with **adb**
```bash
adb install -r pinstore/dist/pinstore.apk
```

Insert the correct code that is `7498`
And we got the flag
![[bside_pinlock3.png]]

I hope you found it useful (: