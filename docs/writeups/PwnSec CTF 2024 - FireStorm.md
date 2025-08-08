**Description**: Descriptions are boring, just solve the challenge meh!
**Download content**: https://lautarovculic.com/my_files/firestorm.zip

![[pwnSec_firestorm1.png]]

Install the **apk** with **ADB**
```bash
adb install -r FireStorm.apk
```

Then, let's *decompile it* with **apktool**
```bash
apktool d FireStorm.apk
```

Open **jadx** (GUI version) for *look the Java code* and inspect it.
We can see in the **MainActivity** the following code
```java
public String Password() {
    StringBuilder sb = new StringBuilder();
    String string = getString(R.string.Friday_Night);
    String string2 = getString(R.string.Author);
    String string3 = getString(R.string.JustRandomString);
    String string4 = getString(R.string.URL);
    String string5 = getString(R.string.IDKMaybethepasswordpassowrd);
    String string6 = getString(R.string.Token);
    
    sb.append(string.substring(5, 9));
    sb.append(string4.substring(1, 6));
    sb.append(string2.substring(2, 6));
    sb.append(string5.substring(5, 8));
    sb.append(string3);
    sb.append(string6.substring(18, 26));
    
    return generateRandomString(String.valueOf(sb));
}

public native String generateRandomString(String str);
```

The following code takes some **strings** from the file **`strings.xml`**.
The password would be predictable **except that there is a function that generates a random string**.
So we will have to call the function, to obtain the output (**return**) of the *generated password*.
For this, we will use **frida**.
Here's a simple script
```javascript
Java.perform(function () {
    function locatePassword() {
        console.log("[*] Attempting to locate MainActivity...");

        Java.choose("com.pwnsec.firestorm.MainActivity", {
            onMatch: function (activityInstance) {
                console.log("[+] MainActivity found: " + activityInstance);

                try {
                    console.log("[*] Calling Password()...");
                    let password = activityInstance.Password();
                    console.log("[+] Password obtained: " + password);
                } catch (err) {
                    console.error("[-] Error while fetching Password(): " + err.message);
                }
            },
            onComplete: function () {
                console.log("[*] MainActivity search completed.");
            }
        });
    }

    const delayMs = 5000;
    console.log(`[!] Delaying execution by ${delayMs / 1000} seconds...`);
    setTimeout(function () {
        console.log("[*] Proceeding to locate Password...");
        locatePassword();
    }, delayMs);
});
```

We run the app and script, then, we can get this output:
```bash
Attaching...
[!] Delaying execution by 5 seconds...
[Redmi Note 8::PID::26744 ]-> [*] Proceeding to locate Password...
[*] Attempting to locate MainActivity...
[+] MainActivity found: com.pwnsec.firestorm.MainActivity@612f258
[*] Calling Password()...
[+] Password obtained: C7_dotpsC7t7f_._In_i.IdttpaofoaIIdIdnndIfC
[*] MainActivity search completed.
[Redmi Note 8::PID::26744 ]->
```

My temporal password is `C7_dotpsC7t7f_._In_i.IdttpaofoaIIdIdnndIfC`.
So, what can we do with the password?

Checking the **`strings.xml`** file in the *resources folder* we can see that there are a **firebase** service.
```XML
<string name="firebase_database_url">https://firestorm-9d3db-default-rtdb.firebaseio.com</string>
<string name="firebase_email">TK757567@pwnsec.xyz</string>
<string name="gcm_defaultSenderId">692664198166</string>
<string name="google_api_key">AIzaSyAXsK0qsx4RuLSA9C8IPSWd0eQ67HVHuJY</string>
<string name="google_app_id">1:692664198166:android:505d0780d7d630846dc137</string>
<string name="google_crash_reporting_api_key">AIzaSyAXsK0qsx4RuLSA9C8IPSWd0eQ67HVHuJY</string>
<string name="google_storage_bucket">firestorm-9d3db.appspot.com</string>
```

We have an *email*! And a *password*. So, let's log in!

You need install some packages and modules, like `pyrebase4`
After some problems, I was run
```bash
pip uninstall pyrebase pyrebase4 requests urllib3
pip install --upgrade requests urllib3 pyrebase4
```

Then
```python
import pyrebase

# Config
firebase_settings = {
    "apiKey": "AIzaSyAXsK0qsx4RuLSA9C8IPSWd0eQ67HVHuJY",
    "authDomain": "firestorm-9d3db.firebaseapp.com",
    "databaseURL": "https://firestorm-9d3db-default-rtdb.firebaseio.com",
    "storageBucket": "firestorm-9d3db.appspot.com",
    "projectId": "firestorm-9d3db"
}

# Init
firebase_instance = pyrebase.initialize_app(firebase_settings)

# Auth
auth_service = firebase_instance.auth()
user_email = "TK757567@pwnsec.xyz"
user_password = "C7_dotpsC7t7f_._In_i.IdttpaofoaIIdIdnndIfC"

try:
    # Log In and get token
    print("[*] Authenticating user...")
    auth_user = auth_service.sign_in_with_email_and_password(user_email, user_password)
    token = auth_user["idToken"]
    print("[+] Authentication successful.")

    # Access
    print("[*] Accessing database...")
    database_service = firebase_instance.database()
    data = database_service.get(token).val()
    print("[+] Database content:")
    print(data)

except Exception as error:
    print("[-] An error occurred: {}".format(error))
```

Execute the script and get the flag!
```bash
python3 connectFirebase.py

[*] Authenticating user...
[+] Authentication successful.
[*] Accessing database...
[+] Database content:
PWNSEC{C0ngr4ts_Th4t_w45_4N_345y_P4$$w0rd_t0_G3t!!!_0R_!5_!t???}
```

Flag: **`PWNSEC{C0ngr4ts_Th4t_w45_4N_345y_P4$$w0rd_t0_G3t!!!_0R_!5_!t???}`**

I hope you found it useful (: