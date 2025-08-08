![[pinned1.png]]
**Difficult:** Easy
**Category**: Mobile
**OS**: Android

**Description**: This app has stored my credentials and I can only login automatically. I tried to intercept the login request and restore my password, but this seems to be a secure connection. Can you help bypass this security restriction and intercept the password in plaintext?

---

Download the **.zip** file and **extract** with **hackthebox** password.
The **README.txt** file say that we need an **Android >12 (API 29)**

Let’s extract the **.apk** file with **apktool**
```bash
apktool d pinned.apk
```

And install it with **adb**
```bash
adb install -r pinned.apk
```

![[pinned2.png]]

Umh, okey.
Let’s check the **source code**.

We can see that the **password** is **1234567890987654**
```bash
if (mainActivity.s.getText().toString().equals("bnavarro") && mainActivity.t.getText().toString().equals("1234567890987654")) {
            StringBuilder g = outline.g("uname=bnavarro&pass=");
            StringBuilder sb = new StringBuilder();
```

But, the **description** say that we need **do** a **SSL** **Pinning Bypass**.

You don’t know about intercept **APP** **Traffic** with **Burpsuite** and **Bypass SSL**, I recommend read this two post
`https://lautarovculic.com/intercept-android-app-traffic-with-burpsuite/`
`https://lautarovculic.com/bypass-restrictions-with-frida/`

Once all **setup**, we need an **Javasript** code **that bypass** the **SSL**.
```javascript
Java.perform(function () {
// Helper function to bypass SSL pinning by returning a custom TrustManager
function bypassSSL() {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustManager = Java.registerClass({
        name: 'org.frida.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) {},
            checkServerTrusted: function (chain, authType) {},
            getAcceptedIssuers: function () { return []; }
        }
    });

    var TrustManagers = [TrustManager.$new()];
    var SSLContextInit = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
    SSLContextInit.implementation = function (keyManager, trustManager, secureRandom) {
        SSLContextInit.call(this, keyManager, TrustManagers, secureRandom);
    };

    console.log('SSL pinning bypass active');
}

// Bypass okhttp3
try {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var Builder = OkHttpClient.Builder;
    Builder.sslSocketFactory.overload('javax.net.ssl.SSLSocketFactory', 'javax.net.ssl.X509TrustManager').implementation = function (sslSocketFactory, trustManager) {
        var newTrustManager = TrustManager.$new();
        return this.sslSocketFactory.call(this, sslSocketFactory, newTrustManager);
    };
    console.log('Bypassed OkHttpClient SSL pinning');
} catch (e) {
    console.log('Failed to bypass OkHttpClient: ' + e);
}

// Bypass TrustManager
try {
    bypassSSL();
} catch (e) {
    console.log('Failed to bypass TrustManager: ' + e);
}
```


There are a **generic SSL Pinning** **Bypass** script, we can run it with **Frida and Burpsuite** running in background
```bash
frida -U -f com.example.pinned -l sslPinning.js
```
And then, we need log in with the creds.

But, if we go to **Burpsuite**, let’s check that in the **POST** we see the **flag**
![[pinned3.png]]

I hope you found it useful (: