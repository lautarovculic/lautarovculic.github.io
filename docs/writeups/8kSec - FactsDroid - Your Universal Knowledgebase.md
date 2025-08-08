**Description**: FactsDroid is the ultimate knowledge companion that delivers fascinating facts right to your fingertips!

**Link**: https://academy.8ksec.io/course/android-application-exploitation-challenges

![[8ksec-FactsDroid_1.png]]

Install the `.apk` using **ADB**
```bash
adb install -r FactsDroid.apk
```

We can see that the application get a *random fact* every time that we press the **Random Fact** button.
I don't know if this issue is due to my devices, or is intended.
But I receive the message:
- *Failed to fetch fact. API might be down*

The *High-Rated* button probably is *out of scope* in this challenge. So, we will focus on the first mentioned button.

So, let's inspect the **source code** using **JADX**.
We *didn't find anything interesting in `AndroidManifest.xml`*. But looking at **`MainActivity`** class we noticed that:
```java
public final class MainActivity extends AbstractActivityC0004e {
    public static final /* synthetic */ int f502g = 0;
    public final String f503f = "com.eightksec.factsdroid/root_check";
}
```

Inspecting the `f502g` variable, we find that:
```java
public void g(C.a aVar, O.j jVar) {
    boolean z2;
    boolean z3;
    boolean z4 = true;
    int i2 = MainActivity.f502g;
    h.e((MainActivity) this.f0b, "this$0");
    h.e(aVar, "call");
    if (!h.a((String) aVar.f4c, "isDeviceRooted")) {
        jVar.b();
        return;
    }
[...]
[...]
[...]
```

So, **we have a root checker** that, in my case, *due to the way I rooted my Android 14 device, does not detect it*.
But this *could be bypassed with a simple Frida script*.

Let's decompile the `.apk` using **apktool**
```bash
apktool d FactsDroid.apk
```

Inside, we found this certificate:
```bash
tree FactsDroid/assets/flutter_assets/assets/certs
```
Output:
```bash
FactsDroid/assets/flutter_assets/assets/certs
└── uselessfacts_jsph_pl.crt
```

So, probably the app originally **make a request** to:
- https://uselessfacts.jsph.pl//api/v2/facts/random

Let's inspect the *libraries* that apktool has extracted.
First, we need *know what architecture our device is*.
```bash
adb shell getprop ro.product.cpu.abi
```
In my case, `x86_64`

So, let's list the libraries:
```bash
tree FactsDroid/lib/x86_64
```
Output:
```bash
FactsDroid/lib/x86_64
├── libapp.so
└── libflutter.so
```

Let's *focus* in `libapp.so` library.
We can use *blutter* tool for decompile and *translate the code into a human-readable* assembly code.
- https://github.com/worawit/blutter
But, for blutter tool use, we need decompile the `arm64-v8a` libraries.

After install it, we can use this command:
```bash
mkdir out_factsdroid_arm64-v8a && python3 blutter.py FactsDroid/lib/arm64-v8a out_factsdroid_arm64-v8a
```

Inside of `out_factsdroid_arm64-v8a` directory we found some new `.txt` and `.dart` files and directories.  
*Take a personal inspection of each for your curiosity, I will continue for useful code*

Inside of `out_factsdroid_arm64-v8a`, we can search for some useful keywords:
```bash
grep -Rni "useless" .
```

We can see a string that probably craft an HTTP connection, you can see that with this command:
```bash
sed -n '10700,10714p' pp.txt
```
Output:
```bash
[pp+0xb450] Field <DatabaseHelper.instance>: static late final (offset: 0x8b8)
[pp+0xb458] String: "uselessfacts.jsph.pl"
[pp+0xb460] String: "/api/v2/facts/random"
[pp+0xb468] List(17) [0, 0x7, 0x6, 0x1, "host", 0x3, "pathSegments", 0x5, "port", 0x4, "queryParameters", 0x6, "scheme", 0x1, "userInfo", 0x2, Null]
[pp+0xb470] String: "Invalid IPv6 host entry."
[pp+0xb478] String: "Invalid end of authority"
[pp+0xb480] String: "ThisIsAVeryInsecureHardcodedKey!"
[pp+0xb488] String: "_key@509261892"
[pp+0xb490] String: "_encrypter@509261892"
[pp+0xb498] Obj!AESMode@493111 : {
  Super!_Enum : {
    off_8: int(0x0),
    off_10: "cbc"
  }
}
```
We can confirm the call to the website mentioned above.

To *intercept traffic from an app made in Flutter* and *bypass all protection mechanisms*, the best script we can use today is the one developed by NVISO Security:
- https://github.com/NVISOsecurity/disable-flutter-tls-verification

The NVISO script, **injected with Frida**, locates the **internal BoringSSL function that validates the X.509 string** (`ssl_verify_peer_cert`) in `libflutter.so/libapp.so` using *byte pattern matching and intercepts it*. in the hook, it **forces the return value to 0** (`VERIFIE`D) and *overrides the verification callback*, so that *any certificate* is *accepted without modifying the APK or moving CAs*: Flutter's *pinning* and *TLS validation* are **completely disabled at runtime**.

So, let's execute this frida script.
Running the *FactsDroid* app and your `frida-server` in the device, in our client we must run:
```bash
frida -U "FactsDroid" -l disable-flutter-tls.js
```
Output:
```bash
Attaching...
[+] Pattern version: May 19 2025
[+] Arch: x64
[+] Platform:  linux
[ ] Locating Flutter library 1/5
[+] Flutter library located
[+] ssl_verify_peer_cert found at offset: 0x7c4c99
[+] ssl_verify_peer_cert has been patched
[Android Emulator 5554::FactsDroid ]->
```

Noticed that if you now try get a *Random Fact*, now it's works!
This was thanks to the NVISO script.

But now, **we need to intercept the traffic**!
We can use **BurpSuite for this**. First, *install and configure the proxy*.

*There are already many blogs, websites, and tutorials on how to do this, so I'll move on to capturing the request*

The **request made by the application when we click on Random Facts is as follows**:
```HTTP
GET /api/v2/facts/random HTTP/2
Host: uselessfacts.jsph.pl
User-Agent: Dart/3.7 (dart:io)
Accept-Encoding: gzip, deflate, br
```
Response:
```HTTP
HTTP/2 200 OK
Access-Control-Allow-Headers: Accept, Content-Type, Content-Length, Accept-Encoding, Authorization
Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS
Access-Control-Allow-Origin: *
Content-Type: application/json; charset=UTF-8
Date: Tue, 29 Jul 2025 13:15:26 GMT
Server: nginx
Content-Length: 279

{
  "id": "e5255a3e28b8b10516c8188aafc3bdd2",
  "text": "A dragonfly has a lifespan of 24 hours.",
  "source": "djtech.net",
  "source_url": "http://www.djtech.net/humor/useless_facts.htm",
  "language": "en",
  "permalink": "https://uselessfacts.jsph.pl/api/v2/facts/e5255a3e28b8b10516c8188aafc3bdd2"
}
```

We must perform the work under the **text parameter**:
- `"text": "A dragonfly has a lifespan of 24 hours."`

Although we could complete the challenge request, I decided to use **iptables** and **mitmproxy**. Flutter’s `HttpClient` ignores the system proxy; that’s why we use **DNAT** with `iptables/mitmproxy`.

Let's *configure our device* with *iptables* to **redirect traffic to our host and port**.
In your `adb shell` session *as root*, run:
```bash
iptables -t nat -I OUTPUT -p tcp --dport 443 -j DNAT --to $IP:$PORT
```
And
```bash
iptables -t nat -I OUTPUT -p tcp --dport 80  -j DNAT --to $IP:$PORT
```
- **OUTPUT** → Everything that *comes out of the device*.
- **DNAT** → Changes the destination to your host.
*In my case -> `$PORT` == 8081*

Now, let's install *mitmproxy* in our computer.
Using `pip3`
```bash
pip3 install mitmproxy
```
Also, we need some libraries
```bash
pip3 install "bcrypt<4" "passlib>=1.7.4"
```

This python script **will replace the text response** when *mitmproxy* do the interception:
```python
from mitmproxy import http, ctx
import json

def response(flow: http.HTTPFlow):
    if "/facts/random" in flow.request.path:
        data = flow.response.json()
        data["text"]   = "Lautaro has solved FactsDroid"
        flow.response.text = json.dumps(data)
```

Important remember:
- Deactivate proxy in your device, and BurpSuite.
- NVISO script must continue running in background.

Run *mitmproxy*
```bash
mitmproxy -s facts_replace.py -p 8081
```
![[8ksec-FactsDroid_2.png]]

*To restore iptables rules* (flush NAT tables)
```bash
iptables -t nat -F
```
*Notice that if you rate with >= 4 stars you custom fact, the app will remember that!*

I hope you found it useful (: