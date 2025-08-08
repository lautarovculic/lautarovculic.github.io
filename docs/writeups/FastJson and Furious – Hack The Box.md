![[fastjson1.png]]
**Difficult:** Easy
**Category**: Mobile
**OS**: Android

**Description**: A couple years ago I was experimenting with Android Development and I created this application to hide my secret, but now I forgot how to get it back. Can you help me?

----

First, download the **.zip** file and extract them with **hackthebox** password.
Then, we’ll use **apktool** for decompile and extract the **application content**.
```bash
apktool d app-release.apk
```

We can see that the compiled version **SDK** is 33, then, I’ll use an **Genymotion** Android device **API 31**.
Install the apk file with
```bash
adb install -r app-release.apk
```

The app looks like
![[fastjson2.png]]

The **package** is
```bash
hhhkb.ctf.fastjson_and_furious
```

After read the java **source code** of the **MainActivity.java** class, we can notice that
```java
public class MainActivity extends AppCompatActivity {
    public static String POSTFIX = "20240227";
    public static boolean succeed = false;
[...]
```

The **succeed** variable is set in **false**.
And the **function calcHash** ever will return **“ ”** if **succeed** is **false**.
Then, we need modify the **MainActivity.smali** code, and change **false** for **true**.

```bash
smali_classes2/hhhkb/ctf/fastjson_and_furious
├── Flag.smali
├── MainActivity$1.smali
├── MainActivity.smali
├── R$color.smali
├── R$drawable.smali
├── R$id.smali
├── R$layout.smali
├── R$mipmap.smali
├── R$string.smali
├── R$style.smali
├── R$xml.smali
├── R.smali
└── ui
```

![[fastjson3.png]]

Now we need **rebuild** the apk
```bash
apktool b app-release -o patchedFast.apk
```

**Align** the apk
```bash
zipalign -v -p 4 patchedFast.apk patchedFastAligned.apk
```

Generate a **new key**
```bash
keytool -genkey -v -keystore my-release-key.keystore -alias my-key-alias -keyalg RSA -keysize 2048 -validity 10000
```

**Sign** the apk
```bash
apksigner sign --ks my-release-key.keystore --out patchedFastAlignedSigned.apk patchedFastAligned.apk
```

**Install** the apk
```bash
adb install -r patchedFastAlignedSigned.apk
```

And if we go to **jadx**, we can see that the **MainActivity.java** class is now **patched**.
![[fastjson4.png]]

Then, now if we send a **valid** **json**
```json
{"username":"admin","password":"1234"}
```

We get this
![[fastjson5.png]]

Assuming that now the app work correctly, let’s keep reviewing the source code searching “hints”
Then, the app now is waiting for a **json** string.
And this need **2** **keys**, we can conclude that because

```java
JSONObject parseObject = JSON.parseObject(str.replace("\":", POSTFIX + "\":"));
            if (parseObject.keySet().size() != 2) {
                return "";
```


If the **key** size isn’t 2, then return nothing.
We can see in the class
```bash
com.alibaba.fastjson.JSON
```

The following information
```java
public abstract class JSON implements JSONStreamAware, JSONAware {
    public static final String DEFAULT_TYPE_KEY = "@type";
    public static final String VERSION = "1.1.52";
[...]
```

After a simple research, I found this article
[https://jfrog.com/blog/cve-2022-25845-analyzing-the-fastjson-auto-type-bypass-rce-vulnerability/](https://jfrog.com/blog/cve-2022-25845-analyzing-the-fastjson-auto-type-bypass-rce-vulnerability/)
Then, after some hours, I conclude that we can craft the **key 1** (with @type vulnerability) and **key 2**, the **succeed** that we fixed for true.

We need a **hinted** **java** **class** for this param.
```bash
hhhkb.ctf.fastjson_and_furious.Flag
```

The final json looks like
```json
{"@type":"hhhkb.ctf.fastjson_and_furious.Flag","success":true}
```

![[fastjson6.png]]

I hope you found it useful (: