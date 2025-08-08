![[apkrypt1.png]]
**Difficult:** Easy
**Category**: Mobile
**OS**: Android

**Description**: Can you get the ticket without the VIP code?

----

Download the **zip** file and extract with the **hackthebox** password.
There are a **README.txt** file that say
1. Install this application in an API Level 29 or earlier (i.e. Android 10.0 (Google APIs)).

Decompile the **apk** with **apktool**
```bash
apktool d APKrypt.apk
```

And install it with **adb**
```bash
adb install -r APKrypt.apk
```

![[apkrypt2.png]]

Let’s check the **source code** with **jadx**
We can see some interesting in the **MainActivity**
```java
protected void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    setContentView(R.layout.activity_main);
    this.b1 = (Button) findViewById(R.id.button);
    this.ed1 = (EditText) findViewById(R.id.editTextVipCode);
    this.b1.setOnClickListener(new View.OnClickListener() { // from class: com.example.apkrypt.MainActivity.1
        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            try {
                if (MainActivity.md5(MainActivity.this.ed1.getText().toString()).equals("735c3628699822c4c1c09219f317a8e9")) {
                    Toast.makeText(MainActivity.this.getApplicationContext(), MainActivity.decrypt("k+RLD5J86JRYnluaZLF3Zs/yJrVdVfGo1CQy5k0+tCZDJZTozBWPn2lExQYDHH1l"), 1).show();
                } else {
                    Toast.makeText(MainActivity.this.getApplicationContext(), "Wrong VIP code!", 0).show();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    });
}
```

```java
public static String md5(String str) {
    try {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        messageDigest.update(str.getBytes());
        byte[] digest = messageDigest.digest();
        StringBuffer stringBuffer = new StringBuffer();
        for (byte b : digest) {
            stringBuffer.append(Integer.toHexString(b & 255));
        }
        return stringBuffer.toString();
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
        return "";
    }
}

public static String encrypt(String str) throws Exception {
    Key generateKey = generateKey();
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(1, generateKey);
    return Base64.encodeToString(cipher.doFinal(str.getBytes("utf-8")), 0);
}

public static String decrypt(String str) throws Exception {
    Key generateKey = generateKey();
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(2, generateKey);
    return new String(cipher.doFinal(Base64.decode(str, 0)), "utf-8");
}

private static Key generateKey() throws Exception {
    return new SecretKeySpec("Dgu8Trf6Ge4Ki9Lb".getBytes(), "AES");
}
```

In the first block we have the **onCreate** method (when the app is executed, and then we have 4 functions: **md5**, **encrypt**, **decrypt** and **generateKey**.

But I’ll keep this piece of code
```java
public void onClick(View view) {
                try {
                    if (MainActivity.md5(MainActivity.this.ed1.getText().toString()).equals("735c3628699822c4c1c09219f317a8e9")) {
                        Toast.makeText(MainActivity.this.getApplicationContext(), MainActivity.decrypt("k+RLD5J86JRYnluaZLF3Zs/yJrVdVfGo1CQy5k0+tCZDJZTozBWPn2lExQYDHH1l"), 1).show();
                    }
```


If we modify the **smali code**, we can get the flag without any data on the **textbox**
Letme explain,
The code **onClick** have a **smali code** that is represented as
```smali
.method public onClick(Landroid/view/View;)V
    .registers 4

    .line 36
    :try_start_0
    iget-object p1, p0, Lcom/example/apkrypt/MainActivity$1;->this$0:Lcom/example/apkrypt/MainActivity;

    iget-object p1, p1, Lcom/example/apkrypt/MainActivity;->ed1:Landroid/widget/EditText;

    invoke-virtual {p1}, Landroid/widget/EditText;->getText()Landroid/text/Editable;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Lcom/example/apkrypt/MainActivity;->md5(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    const-string v0, "735c3628699822c4c1c09219f317a8e9"

    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_2d

    .line 37
    iget-object p1, p0, Lcom/example/apkrypt/MainActivity$1;->this$0:Lcom/example/apkrypt/MainActivity;

    invoke-virtual {p1}, Lcom/example/apkrypt/MainActivity;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    const-string v0, "k+RLD5J86JRYnluaZLF3Zs/yJrVdVfGo1CQy5k0+tCZDJZTozBWPn2lExQYDHH1l"

    invoke-static {v0}, Lcom/example/apkrypt/MainActivity;->decrypt(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const/4 v1, 0x1

    invoke-static {p1, v0, v1}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object p1

    invoke-virtual {p1}, Landroid/widget/Toast;->show()V

    goto :goto_42

    .line 39
    :cond_2d
    iget-object p1, p0, Lcom/example/apkrypt/MainActivity$1;->this$0:Lcom/example/apkrypt/MainActivity;

    invoke-virtual {p1}, Lcom/example/apkrypt/MainActivity;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    const-string v0, "Wrong VIP code!"

    const/4 v1, 0x0

    invoke-static {p1, v0, v1}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object p1

    invoke-virtual {p1}, Landroid/widget/Toast;->show()V
    :try_end_3d
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_3d} :catch_3e

    goto :goto_42

    :catch_3e
    move-exception p1

    .line 42
    invoke-virtual {p1}, Ljava/lang/Exception;->printStackTrace()V

    :goto_42
    return-void
.end method
```

We need look at this line:
```smali
if-eqz p1, :cond_2d
```

That say
“_if “code” is p1 (encrypted code), then cond_2d that is the toast message with the flag_”
If-eqz is **equal**
If-nez is **not-equal**

Then, we go to
```bash
/APKrypt/smali/com/example/apkrypt/
```

And with **nano** edit the file
```bash
nano MainActivity\$1.smali
```

Search the onClick **method** (**line 65 probably**)
And change **if-eqz** to **if-nez**
![[apkrypt3.png]]

Save the file and go to the start of the folder
**Build** a new apk with **apktool**
```bash
apktool b APKrypt
```

And go to **/APKrypt/dist/**
Then generate a new key with keytool
```bash
keytool -genkey -keystore lautaro.keystore -validity 1000 -alias lautaro
```

Sign the new apk with **jarsigner**
```bash
jarsigner -keystore lautaro.keystore -verbose APKrypt.apk lautaro
```

Delete the previous **apk installed**
And install the new apk with **adb**
```bash
adb install -r APKrypt.apk
```

Now run again the **app** and press the button
![[apkrypt4.png]]

I hope you found it useful (: