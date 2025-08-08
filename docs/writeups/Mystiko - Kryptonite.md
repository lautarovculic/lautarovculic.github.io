**Category**: Crypto
**Description**: This challenge intends to show how to enumerate android apps in search for hidden information.

Download **APK**: https://lautarovculic.com/my_files/kryptonite.apk

![[mystiko_kryptonite1.png]]

Install the **APK** file with **ADB**
```bash
adb install -r krypto.apk
```

We can see that we have an **encrypt/decrypt** message app.
The text is in *leet speak*.
And the title says: *`AES is kryptonite for haxors`*

Notice that, trying the *length* of the key randomly, I see the correct char length is **16**.
Also, check in the *source code*, in `MainActivity` we can verify the length:
```java
if (obj2.length() != 16 && obj2.length() != 24 && obj2.length() != 32) {
    Toast.makeText(MainActivity.this.getApplicationContext(), "Wr0Ng k3Y L3n6tH", 0).show();
}
```

So, let's **analyze the source code** with **jadx**.
The **package name** is **`com.example.kryptonite`**

We have **two activities**.
- `MainActivity`
- `H1dD3N`

```XML
<application
    android:theme="@style/Theme.AppCompat.NoActionBar"
    android:label="@string/app_name"
    android:icon="@mipmap/ic_launcher"
    android:allowBackup="true"
    android:supportsRtl="true"
    android:roundIcon="@mipmap/ic_launcher_round"
    android:appComponentFactory="androidx.core.app.CoreComponentFactory">
    <activity android:name="com.example.kryptonite.H1dD3N"/>
    <activity android:name="com.example.kryptonite.MainActivity">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
    </activity>
</application>
```

The **`H1dD3N`** activity must be launched with **ADB**.
I seen a `.db` file in **jadx**. Inside of `assets` directory. Let's inspect that.
```bash
mkdir kryp && cd kryp && unzip ../krypto.apk
```

Then:
```bash
sqlite3 assets/databases/default.db
```

```bash
SQLite version 3.44.3 2024-03-24 21:15:01
Enter ".help" for usage hints.
sqlite> .headers on
sqlite> .tables
test
sqlite> select * from test;
user|secret
J0hn|XAc860TQ62HaVTjOGV5egywXXWS0hUc6yOR/0eu5aQM=
P4u7|bq3G0iIKEKfb4bJcqvpsziaHZLEsEZfzxRY21d9yV3g=
M4r14|vEpr9q0DVMSbe7pDyqz7TtjWEhxZZ03uDcksStPArvo=
```

We can see some **AES** text.
Then, let's see the **`H1dD3N`** activity content using **ADB**
```bash
am start -n com.example.kryptonite/com.example.kryptonite.H1dD3N
```

We can see another **AES** text:
```bash
OUSRuRRHNCtyyvHMQq3G+9QCE0z+tuHB/bWq8EZG3YGg/4H1uflzq1NzT2faKtMy
```

Probably the **message**?
In the **java code** of `H1dD3N` activity, we can see:
```java
C0508a.m1814f(H1dD3N.this, R.string.c5, "test12");
C0508a.m1814f(H1dD3N.this, R.string.c6, "test12 (re-testing...)");
```

The `c5` and `c6` string resources looks suspicious.
Let's take a look to the `res/values/strings.xml`
```XML
<string name="c5">Kyrpt... Error found when processing current gas element...</string>
<string name="c6">KrYp70N1t3_k1LLz_$uPerM4N&amp;H4ck3R</string>
```

We can see `KrYp70N1t3_k1LLz_$uPerM4N&amp;H4ck3R`
But, `&amp;` is `&`
Finally, the **key** (*16 chars*) is:
**`KrYp70N1t3_k1LLz_$uPerM4N&H4ck3R`**

Using
```bash
J0hn|XAc860TQ62HaVTjOGV5egywXXWS0hUc6yOR/0eu5aQM=
P4u7|bq3G0iIKEKfb4bJcqvpsziaHZLEsEZfzxRY21d9yV3g=
M4r14|vEpr9q0DVMSbe7pDyqz7TtjWEhxZZ03uDcksStPArvo=
```

In the message and the *previous* key. We can get the followings **plain text** messages:
```bash
J0hn = Pl4N37_kRYp70N_X-P70d3d
P4u7 = (%)KrYpT0NyT3_4_L1F3~
M4r14 = #36kRyPtoN_GaZ_4_LuNCH?@
```

But, what about the **AES text** in the **`H1dD3N`** activity?
`OUSRuRRHNCtyyvHMQq3G+9QCE0z+tuHB/bWq8EZG3YGg/4H1uflzq1NzT2faKtMy`

Let's use as message, and, *try each plain text* that we get previously.
After 3 tries, if we use the `M4r14` **key** (`#36kRyPtoN_GaZ_4_LuNCH?@`), we got the flag.

![[mystiko_kryptonite2.png]]

Flag: **`Mystiko{AES_Krypt0nite_f0r_pr1v8_L1f3}`**

I hope you found it useful (: