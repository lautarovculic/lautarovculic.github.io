![[ieCTF1.png]]
**Difficulty:** Moderate
**Skills:** Android
**Flags:** 1

----

## Flag 1/1
First, we need wait until the APK is building.
Download the **.APK** file.
Decompile the **.APK** with _apktool_

```bash
apktool d level13.apk
```

- The target SDK is **28** (**Android 9.0**).

Then, install the **APK** _with ADB_ to our Android Device, I use Genymotion.
```bash
adb install level13.apk
```

Open the app and
![[ieCTF2.png]]

So let’s order this..
When _the App is open_, we see an **WebView**:
```bash
/appRoot?&hash=61f4518d844a9bd27bb971e55a23cd6cf3a9f5ef7f46285461cf6cf135918a1a
```

And if we click on “**Flag**”, we will _redirect to_:
```bash
/appRoot/flagBearer
```

And an **Invalid request** message.
So this made me think that the _key is the URL_.
Well.. let’s _inspect the **Java** source code_. With **jadx-gui**
_Note: URL is your private Hacker101 instance_.

**MainActivity.java** > **onCreate**
```java
public void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    setContentView(R.layout.activity_main);
    WebView webView = (WebView) findViewById(R.id.webview);
    webView.setWebViewClient(new WebViewClient());
    Uri data = getIntent().getData();
    String str = "https://URL.ctf.hacker101.com/appRoot";
    String str2 = BuildConfig.FLAVOR;
    if (data != null) {
        str2 = data.toString().substring(28);
        str = "https://URL.ctf.hacker101.com/appRoot" + str2;
    }
    if (!str.contains("?")) {
        str = str + "?";
    }
    try {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update("s00p3rs3cr3tk3y".getBytes(StandardCharsets.UTF_8));
        messageDigest.update(str2.getBytes(StandardCharsets.UTF_8));
        webView.loadUrl(str + "&hash=" + String.format("%064x", new BigInteger(1, messageDigest.digest())));
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    }
}
```

Looking and analyzing the code, I my head this is:
```java
str = https://URL.ctf.hacker101.com/appRoot
```

We can assume that **str** + **str2** is:
```bash
https://URL.ctf.hacker101.com/appRoot/flagBearer
```

Because:
```java
if (data != null) {
            str2 = data.toString().substring(28);
            str = "https://URL.ctf.hacker101.com/appRoot" + str2;
        }
```

And then:
```java
if (!str.contains("?")) {
            str = str + "?";
        }
```

If `https://URL.ctf.hacker101.com/appRoot/flagBearer` no contains “?” then, add it.
Until now, we have:
```bash
https://URL.ctf.hacker101.com/appRoot/flagBearer?
```

And in the end, we have:
```java
try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update("s00p3rs3cr3tk3y".getBytes(StandardCharsets.UTF_8));
            messageDigest.update(str2.getBytes(StandardCharsets.UTF_8));
            webView.loadUrl(str + "&hash=" + String.format("%064x", new BigInteger(1, messageDigest.digest())));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
```


So, _now the value of the URL is_:
```bash
https://URL.ctf.hacker101.com/appRoot/flagBearer?&hash=
```

We have the MessageDigest instance, that use **SHA-256**
In _first place_, is **s00p3rs3cr3tk3y**
That in SHA-256 is
```bash
61f4518d844a9bd27bb971e55a23cd6cf3a9f5ef7f46285461cf6cf135918a1a
```

(Remember the first URL)
But the messageDigest is update with the **str2** value, that is **/flagBearer**
Then, this is the “**key**”:
```bash
s00p3rs3cr3tk3y/flagBearer
```


The SHA-256 can be calculated with this script that I made:
```python
import hashlib

# key
key = "s00p3rs3cr3tk3y/flagBearer"

# get SHA-256
hash_sha256 = hashlib.sha256(key.encode()).hexdigest()

# print
print("[*] The hash is:", hash_sha256)
print("--------------------------------------------------------------------")
print("Then, the final URL is: https://URL.ctf.hacker101.com/appRoot/flagBearer?&hash=" + hash_sha256)
```


Then, the final URL is
```bash
https://URL.ctf.hacker101.com/appRoot/flagBearer?&hash=<HASH>
```

At this point you can check your desktop browser to get the flag. But we can try “_**fix**_” the App (_or try get the Flag easily_).
In the **MainActivity.smali** code, we can replace the first URL (When the WebView is created/loaded).

```smali
.line 24
invoke-virtual {v0}, Landroid/content/Intent;->getData()Landroid/net/Uri;

move-result-object v0

const-string v1, "https://URL.ctf.hacker101.com/appRoot"

const-string v2, ""

if-eqz v0, :cond_0

.line 28
```


At the line **55** of the file, we can replace `https://URL.ctf.hacker101.com/appRoot*`
to
`https://URL.ctf.hacker101.com/appRoot/flagBearer?&hash=HASH`
Then build and sign the new **.APK** and remove the old App, then install.

```bash
apktool b level13
```
```bash
apksigner sign --ks name.keystore --ks-key-alias alias --out apk.apk level13/dist/level13.apk
```
```bash
adb install apk.apk
```

And here is:
![[ieCTF3.png]]

I hope you found it useful (: