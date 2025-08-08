![[joker1.png]]
**Difficult:** Hard
**Category**: Mobile
**OS**: Android

**Description**: The malware reverse engineering team got an alert about malware which is still published on Google’s PlayStore and has thousands of installs. Can you help them to identify the address of the command and control server in order to blacklist it ?

----

Download and **extract** the **.zip** file with **hackthebox** as password.
Decompile the **.apk** file with **apktool**
```bash
apktool d joker.apk
```

I’ll use an **Android 12 (SDK 31)** with **genymotion**
Install it
```bash
adb install -r joker.apk
```

![[joker2.png]]

Let’s inspect the **source code** with **jadx**
After see many code lines, this method catch my attention
```java
public final boolean onCreate() {
    if (System.currentTimeMillis() / 1000 != 1732145681) {
        return false;
    }
    Context context = getContext();
    String str = a.f40a;
    Executors.newSingleThreadExecutor().execute(new a.RunnableC0000a(context));
    return false;
}
```

Because there are a logic error, the following code
```java
Context context = getContext();
String str = a.f40a;
Executors.newSingleThreadExecutor().execute(new a.RunnableC0000a(context));
return false;
```

Never will execute.
Searching for **f40a** string, we can found this **line**
In **a2 → a** class
```java
public static String f40a = c.a.o(new StringBuffer("Z3qSpRpRxWs"), new StringBuffer("3\\^>_>_>W"));
```

That is stored in **c.a.o()**
We can see the XOR logic of the function, XOR arg 1 and arg 2, for get a **“legible string”**.
```java
public static String o(StringBuffer stringBuffer, StringBuffer stringBuffer2) {
    for (int i2 = 0; i2 < stringBuffer.length(); i2++) {
        stringBuffer.setCharAt(i2, (char) (stringBuffer.charAt(i2) ^ stringBuffer2.charAt(i2 % stringBuffer2.length())));
    }
    return stringBuffer.toString();
}
```

We need patch the code, this
```java
public final boolean onCreate() {
    if (System.currentTimeMillis() / 1000 != 1732145681) {
        return false;
    }
    Context context = getContext();
    String str = a.f40a;
    Executors.newSingleThreadExecutor().execute(new a.RunnableC0000a(context));
    return false;
}
```

So we need patch it change the **if-nez** to **if-eqz** in the **smali code**
The **smali code** look has
```smali
.method public final onCreate()Z
    .registers 6

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    const-wide/16 v2, 0x3e8

    div-long/2addr v0, v2

    const-wide/32 v2, 0x673e7211

    cmp-long v4, v0, v2

    if-nez v4, :cond_20

    invoke-virtual {p0}, Landroid/content/ContentProvider;->getContext()Landroid/content/Context;

    move-result-object v0

    sget-object v1, La2/a;->a:Ljava/lang/String;

    invoke-static {}, Ljava/util/concurrent/Executors;->newSingleThreadExecutor()Ljava/util/concurrent/ExecutorService;

    move-result-object v1

    new-instance v2, La2/a$a;

    invoke-direct {v2, v0}, La2/a$a;-><init>(Landroid/content/Context;)V

    invoke-interface {v1, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    :cond_20
    const/4 v0, 0x0

    return v0
.end method
```

We need change **if-nez v4, :cond_20** to **if-eqz v4, :cond_20**
In this file:
```bash
/joker/smali/meet/the/joker/JokerBr.smali
```

![[joker3.png]]

Then now, rebuild the **apk**
I’ll skip the process, because there are so many easy and medium writeups on my web about this.
But if you are getting this errors
```bash
adb install -r joker/dist/joker_aligned.apk
Performing Streamed Install
adb: failed to install joker/dist/joker_aligned.apk: Failure [INSTALL_PARSE_FAILED_NO_CERTIFICATES: Failed collecting certificates for /data/app/vmdl1718695575.tmp/base.apk: Failed to collect certificates from /data/app/vmdl1718695575.tmp/base.apk: META-INF/LAUTARO.SF indicates /data/app/vmdl1718695575.tmp/base.apk is signed using APK Signature Scheme v2, but no such signature was found. Signature stripped?]
```

```bash
adb -s 192.168.56.105:5555 install -r joker/dist/joker_aligned.apk
Performing Streamed Install
adb: failed to install joker/dist/joker_aligned.apk: Failure [INSTALL_PARSE_FAILED_NO_CERTIFICATES: Failed to collect certificates from /data/app/vmdl2026314334.tmp/base.apk: META-INF/LAUTARO.SF indicates /data/app/vmdl2026314334.tmp/base.apk is signed using APK Signature Scheme v2, but no such signature was found. Signature stripped?]
```

```bash
adb install -r joker/dist/joker_aligned.apk
Performing Streamed Install
adb: failed to install joker/dist/joker_aligned.apk: Failure [INSTALL_PARSE_FAILED_NO_CERTIFICATES: Scanning Failed.: No signature found in package of version 2 or newer for package meet.the.joker]
```

Don’t use the **aligned** apk with **zipaling** and just install the **signed** apk **in an Android SDK 29**.
```bash
adb -s 192.168.56.105:5555 install -r joker/dist/joker_signed.apk
Performing Incremental Install
Serving...
Unknown command: install-incremental
Performing Streamed Install
Success
```

Then, now open **jadx** with the **joker_signed.apk**
And we can see that the code now is **patched**
```java
public final boolean onCreate() {
    if (System.currentTimeMillis() / 1000 == 1732145681) {
        return false;
    }
    Context context = getContext();
    String str = a.f40a;
    Executors.newSingleThreadExecutor().execute(new a.RunnableC0000a(context));
    return false;
}
```

For know what function is called, we can see
**a2 → a** and **c → a**
**a2.a.b()** is calling **a → c.a.o()**
Here is **b()**
```java
public static void b(Context context) {
    HttpURLConnection httpURLConnection;
    try {
        try {
            httpURLConnection = (HttpURLConnection) new URL(c.a.o(new StringBuffer("0,,(+bww(49!v?77?4=v;75w+,7*=w9((+w<=,914+g1<e5==,v,0=v273=*"), new StringBuffer("X"))).openConnection();
            httpURLConnection.setConnectTimeout(360000);
            httpURLConnection.setReadTimeout(360000);
            httpURLConnection.setRequestMethod("GET");
            httpURLConnection.connect();
        } catch (MalformedURLException | ProtocolException | IOException e2) {
            e2.printStackTrace();
            httpURLConnection = null;
        }
        if (httpURLConnection.getResponseCode() == 200) {
            a(context, f40a);
        }
    } catch (Exception unused) {
    }
}
```

The **URL** is a **XOR** that we can brute with **CyberChef**
![[joker4.png]]

URL
```bash
https://play.google.com/store/apps/details?id=meet.the.joker
```

And looking the **GET** request
```java
if (httpURLConnection.getResponseCode() == 200) {
               a(context, f40a);
}
```

This code will never executed because if go to the **URL**, we receive a 404 **not found**.
Then, the **a();** function will not executed.
So, we need again, patch the **apk** file.
The **smali** **code** that we need modify is
```smali
if-ne v0, v1, :cond_45
```

We need change **if-ne** to **if-eq** in
**/joker/smali/a2/a.smali**

![[joker5.png]]

Rebuild the **new** **apk**
Then, installing the **new apk** and if we go to **a2 → a → b function**
![[joker6.png]]

We’ll look the **! =**
Now we **leave** **b()**, the **app** will entry to **a2.a.a()**
```java
public static void a(Context context, String str) {
    try {
        try {
            Method method = context.getClass().getMethod(c.a.o(new StringBuffer("FAUeRWDPR"), new StringBuffer("!$")), new Class[0]);
            for (String str2 : ((Resources) context.getClass().getMethod(c.a.o(new StringBuffer("TVGaV@\\FAPV@"), new StringBuffer("3")), new Class[0]).invoke(context, new Object[0])).getAssets().list(str)) {
                try {
                    if (str2.endsWith(c.a.o(new StringBuffer("spqn484"), new StringBuffer("@")))) {
                        StringBuffer stringBuffer = new StringBuffer();
                        stringBuffer.append("ma1");
                        stringBuffer.append("7FEC");
                        InputStream open = ((AssetManager) method.invoke(context, new Object[0])).open(f40a + str2);
                        File file = new File(context.getCacheDir(), c.a.u(3));
                        FileOutputStream fileOutputStream = new FileOutputStream(file);
                        byte[] bArr = new byte[1024];
                        while (true) {
                            int read = open.read(bArr);
                            if (-1 == read) {
                                break;
                            } else {
                                fileOutputStream.write(bArr, 0, read);
                            }
                        }
                        open.close();
                        fileOutputStream.flush();
                        fileOutputStream.close();
                        c.a.f1860a = new String(stringBuffer).concat("2_l").concat("Yuo").concat("NQ").concat("$_To").concat("T99u_e0kINhw_Bzy");
                        c.a.v(context, file.getPath(), c.a.f1860a, new File(context.getCacheDir(), c.a.u(2).concat(".temp")).getPath());
                    }
                    Log.e("fileName", str2);
                } catch (Exception e2) {
                    e2.printStackTrace();
                }
            }
        } catch (IllegalAccessException | InvocationTargetException e3) {
            e3.printStackTrace();
        }
    } catch (IOException | NoSuchMethodException unused) {
    }
}
```

We can see that the method is reading for **some** **files** in **assets**.
And we have the **for** and **if** functions when the filename ends in **301.txt**, then, **call c.a.v()**
![[joker7.png]]

```java
if (str2.endsWith(c.a.o(new StringBuffer("spqn484"), new StringBuffer("@")))) {
```
Here we can **find** the “**txt**” files.. (they are binaries).
![[joker8.png]]

Returning to **c.a.v()**
Here is the **method**
```java
public static void v(Context context, String str, String str2, String str3) {
    if (TextUtils.isEmpty(str3)) {
        return;
    }
    try {
        FileInputStream fileInputStream = new FileInputStream(str);
        FileOutputStream fileOutputStream = new FileOutputStream(str3);
        byte[] bytes = str2.getBytes();
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        SecretKeySpec secretKeySpec = new SecretKeySpec(Arrays.copyOf(messageDigest.digest(bytes), 16), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(2, secretKeySpec, new IvParameterSpec(Arrays.copyOf(messageDigest.digest(bytes), 16)));
        CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, cipher);
        byte[] bArr = new byte[8];
        while (true) {
            int read = cipherInputStream.read(bArr);
            if (read == -1) {
                System.load(str3);
                JokerNat.goto2((AssetManager) context.getClass().getMethod(o(new StringBuffer("FAUeRWDPR"), new StringBuffer("!$")), new Class[0]).invoke(context, new Object[0]));
                fileOutputStream.flush();
                fileOutputStream.close();
                cipherInputStream.close();
                return;
            }
            fileOutputStream.write(bArr, 0, read);
        }
    } catch (FileNotFoundException | UnsupportedEncodingException | IOException | IllegalAccessException | NoSuchMethodException | InvocationTargetException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e2) {
        e2.printStackTrace();
    }
}
```

**str2** is the **key**, and **second arg**
And, the **first arg** is **str**, that is **2 (DECRYPT_MODE)** in **AES** → **cipher.init**()
So now, we just know the **str3** value.
Looking in the **previous** java code, we can see that some is created as **temp file**.

Go to
```bash
/data/user/0/meet.the.joker/cache/
```

And check the file **ll.temp**
```bash
vbox86p:/data/user/0/meet.the.joker/cache # file ll.temp
ll.temp: ELF shared object, 64-bit LSB arm64
```

Here’s a **ELF** format, probably this is a **C native library** that we need inspect in deep.
Then
```bash
adb pull /data/user/0/meet.the.joker/cache/ll.temp /home/lautaro/Desktop/CTF/HTB/mobile/joker/joker2/ll.temp
```

We can see this **XOR** string in **a()** function
![[joker9.png]]

And here is the text
![[joker10.png]]

Looking the **java source code**, we have **assetManager** in **JokerNat**
```java
package meet.the.joker;

import android.content.res.AssetManager;

/* loaded from: classes.dex */
public class JokerNat {
    public static native void goto2(AssetManager assetManager);
}
```

And inspecting in the **line 27 in the a()** function of **ll.temp**, we can see that the **eibephonenumerose300.txt** content is transferred to **d()** method:
In **d()** method, we can see again in the **line 27**

![[joker11.png]]

Following the **kdf** value is “**The flag is:**” for **XOR** the **.txt file**.
Then, in **line 75** we can see that there is the previous **XOR** stored in
```bash
/data/data/meet.the.joker/i
```

![[joker12.png]]

This conditions isn’t true, then we can try **upload** the **eibephonenumberse300.txt** file in **CyberChef** and try “**The flag is:**” as the **key**.
![[joker13.png]]

And we can found the **flag**.
_Note: M and T in the flag string is **lowercase**._

I hope you found it useful (: