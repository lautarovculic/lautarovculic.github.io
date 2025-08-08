**Category**: Forensics
**Description**: An Android application was released for the toaster bots, but it seems like this one is some sort of debug version. Can you discover the presence of any debug information being stored, so we can plug this? You can download the apk here.

**Note**: For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

Download **APK**: https://lautarovculic.com/my_files/ToasterBot.apk

![[droidApp1.png]]

Install the **apk** with
```
adb install -r ToasterBot.apk
```

Decompile the **apk** with **apktool**
```bash
apktool d ToasterBot.apk
```
And now, let's inspect the **source code** with **jadx**

The **MainActivity** in this case is **ToasterActivity**.
That the **java code** is
```java
package picoapp453.picoctf.com.picoapp;  
  
import android.os.Bundle;  
import android.support.v7.app.ActionBarActivity;  
import android.util.Log;  
import android.view.Menu;  
import android.view.MenuItem;  
import android.view.View;  
import android.widget.Toast;  


public class ToasterActivity extends ActionBarActivity {  
    String mystery = "flag is: what_does_the_logcat_say";  


    public void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
        setContentView(C0125R.layout.activity_my);  
    }  


    public boolean onCreateOptionsMenu(Menu menu) {  
        getMenuInflater().inflate(C0125R.menu.f8my, menu);  
        return true;  
    }  


    public boolean onOptionsItemSelected(MenuItem item) {  
        int id = item.getItemId();  
        if (id == C0125R.id.action_settings) {  
            return true;  
        }  
        return super.onOptionsItemSelected(item);  
    }  
  
    public void displayMessage(View view) {  
        Toast.makeText(getApplicationContext(), "Toasters don't toast toast, toast toast toast!", 1).show();  
        Log.d("Debug tag", this.mystery);  
    }  
}
```

This is an so **easy** CTF. Because we just can conclude that this code
```java
Log.d("Debug tag", this.mystery);
```
Can be called with **logcat**
```bash
adb logcat -c && adb logcat
```

Then, just press the **button** and in the log we can see the flag:
```bash
--------- beginning of main
D/Debug tag( 4536): flag is: what_does_the_logcat_say
```

Flag: `what_does_the_logcat_say`
And notice that the flag is **hardcoded** in the **source code** :/
```java
String mystery = "flag is: what_does_the_logcat_say";  
```

Then... Let's make something funny.
Let's try trigger the flag when we **press** the button.
So, for this, we need identify the **smali** file to the **ToasterActivity**.
```bash
ToasterBot
└── picoapp453
    └── picoctf
        └── com
            └── picoapp
                └── ToasterActivity.smali
```

Let's modify this **method**
```smali
.method public displayMessage(Landroid/view/View;)V
    .registers 5
    .param p1, "view"    # Landroid/view/View;

    .prologue
    .line 43
    invoke-virtual {p0}, Lpicoapp453/picoctf/com/picoapp/ToasterActivity;->getApplicationContext()Landroid/content/Context;

    move-result-object v0

    const-string v1, "Toasters don\'t toast toast, toast toast toast!"

    const/4 v2, 0x1

    invoke-static {v0, v1, v2}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object v0

    invoke-virtual {v0}, Landroid/widget/Toast;->show()V

    .line 44
    const-string v0, "Debug tag"

    iget-object v1, p0, Lpicoapp453/picoctf/com/picoapp/ToasterActivity;->mystery:Ljava/lang/String;

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 45
    return-void
.end method
```

Looking the method, we can do some changes.
To modify the Smali code so that the Toast message displays the same string as the one used in the log, we need to **replace the constant string used for the Toast message** with the value of the field `mystery`.

Here's the **new method**
```smali
.method public displayMessage(Landroid/view/View;)V
    .registers 5
    .param p1, "view"    # Landroid/view/View;

    .prologue
    .line 43
    # Call getApplicationContext() to get the Context
    invoke-virtual {p0}, Lpicoapp453/picoctf/com/picoapp/ToasterActivity;->getApplicationContext()Landroid/content/Context;

    # Store the result in v0 (the Context)
    move-result-object v0

    # Get the value of 'mystery' field from the current object (p0)
    iget-object v1, p0, Lpicoapp453/picoctf/com/picoapp/ToasterActivity;->mystery:Ljava/lang/String;

    # Set the Toast length (short in this case)
    const/4 v2, 0x1

    # Use the value of 'mystery' (v1) in the Toast message
    invoke-static {v0, v1, v2}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    # Store the Toast object in v0
    move-result-object v0

    # Show the Toast
    invoke-virtual {v0}, Landroid/widget/Toast;->show()V

    .line 44
    # Define the tag for the debug log
    const-string v0, "Debug tag"

    # Use the value of 'mystery' (v1) for the log message
    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 45
    # End the method
    return-void
.end method
```

Just delete the **old method** and paste the **new method**. Obviously, don't delete all the content. Just replace the method. (Important keep format and tab).

Here a **simple** explanation:
**Removed the constant string for the Toast**: The line `const-string v1, "Toasters don't toast toast, toast toast toast!"` was removed because we're now using the value of `mystery`.

**Retrieve the value of `mystery` before the Toast**: The line `iget-object v1, p0, Lpicoapp453/picoctf/com/picoapp/ToasterActivity;->mystery:Ljava/lang/String;` retrieves the value of `mystery` from the object and stores it in `v1`.

**Use the value of `mystery` in the Toast**: The value stored in `v1` (which is the `mystery` string) is then used as the message for the Toast in the `Toast.makeText` call.


Now we can **rebuild** the apk with **apktool**
```bash
apktool b ToasterBot
```
*ToasterBot* is the **main folder** of the apk.

Then, generate a new key
```bash
keytool -genkey -v -keystore name.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias alias
```

And, at the end, sign with **jarsigner**
```bash
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore name.keystore ToasterBot/dist/ToasterBot.apk alias
```

Now, at the end, **uninstall** the old apk and **install** with **adb** the new apk.
```bash
adb install -r ToasterBot/dist/ToasterBot.apk
```

Launch the app an we'll can see the **flag** as an **Toast Message**
![[droidApp2.png]]

I hope you found it useful (: