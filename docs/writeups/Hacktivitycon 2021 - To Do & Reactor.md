## To Do

**Description**: I made my own app to remind me of all the things I need to do.
**Download**: https://lautarovculic.com/my_files/todo.apk

![[hackticitycon2021_1.png]]

Install the APK file with **ADB**
```bash
adb install -r todo.apk
```

Let's inspect the **source code** with **jadx**.
Meanwhile, we can see that we have an password text field, if we insert any char, we get the message "*Wrong password*".

Looking in the **`com.congon4tor.todo.LoginActivity`** java code, the following content:
```java
public class LoginActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(C0523R.layout.activity_login);
        Button button = (Button) findViewById(C0523R.id.button);
        final TextView textView = (TextView) findViewById(C0523R.id.password);
        final Intent intent = new Intent(this, (Class<?>) MainActivity.class);
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (textView.getText().toString().equals("testtest")) {
                    LoginActivity.this.startActivity(intent);
                } else {
                    Toast.makeText(LoginActivity.this.getApplicationContext(), "Wrong password", 0).show();
                }
            }
        });
    }
}
```

Basically here says that:
if the password is **`testtest`** then, a new activity is launched (`com.congon4tor.todo.MainActivity`).
Else, a toast message is showed (Wrong password).

Just put the password `testtest` and you can get the flag.
Also, looking in the `AndroidManifest.xml` file, we can see that the `MainActivity` is exported.
So, we can **bypass the login** just using **ADB**. Close the app and then run:
```bash
adb shell am start -n com.congon4tor.todo/.MainActivity
```

But, where the notes are stored?
We can see in the `MainActivity` that when is created, call to an *database helper*
```java
public void onCreate(Bundle bundle) {  
        super.onCreate(bundle);  
        setContentView(C0523R.layout.activity_main);  
        MyDatabase myDatabase = new MyDatabase(this);  
        this.f92db = myDatabase;  
        this.todos = myDatabase.getTodos();  
        ArrayList arrayList = new ArrayList();  
        try {
[...]
[...]
[...]
```

The **`MyDatabase`** class code is:
```java
public class MyDatabase extends SQLiteAssetHelper {
    private static final String DATABASE_NAME = "todos.db";
    private static final int DATABASE_VERSION = 1;

    public MyDatabase(Context context) {
        super(context, DATABASE_NAME, null, 1);
    }

    public Cursor getTodos() {
        SQLiteDatabase readableDatabase = getReadableDatabase();
        SQLiteQueryBuilder sQLiteQueryBuilder = new SQLiteQueryBuilder();
        sQLiteQueryBuilder.setTables("todo");
        Cursor query = sQLiteQueryBuilder.query(readableDatabase, new String[]{"id AS _id", "content"}, null, null, null, null, "id ASC");
        query.moveToFirst();
        return query;
    }
}
```

In `AndroidManifest.xml` file we can see that the `android:allowBackup="true"` attribute is true, so, you can basically create with **ADB** a *backup* and then, get the `todo.db` file.
Also, if you got a *rooted device*, just make the following sequential commands:
```bash
adb shell
ginkgo:/ $ su
ginkgo:/ # cp /data/data/com.congon4tor.todo/databases/todos.db /sdcard/
ginkgo:/ # exit
```

Then, pull the `.db` file into our machine:
```bash
adb pull /sdcard/todos.db .
```

```bash
sqlite3 todos.db
SQLite version 3.44.3 2024-03-24 21:15:01
Enter ".help" for usage hints.
sqlite> .headers on
sqlite> .tables
android_metadata  todo
sqlite> select * from todo;
id|content
1|ZmxhZ3s1MjZlYWIwNGZmOWFhYjllYTEzODkwMzc4NmE5ODc4Yn0=
2|VXNlIGFjdHVhbCBlbmNyeXB0aW9uIG5vdCBqdXN0IGJhc2U2NA==
sqlite>
```

The `ZmxhZ3s1MjZlYWIwNGZmOWFhYjllYTEzODkwMzc4NmE5ODc4Yn0=` string is the flag, using `base64 -d` command you can see that:
```bash
echo 'ZmxhZ3s1MjZlYWIwNGZmOWFhYjllYTEzODkwMzc4NmE5ODc4Yn0=' | base64 -d
```

Flag: **`flag{526eab04ff9aab9ea138903786a9878b}`**

## Reactor

**Description**: We built this app to protect the reactor codes
**Download**: https://lautarovculic.com/my_files/reactor.apk

![[hackticitycon2021_2.png]]

Install the APK file with **ADB**
```bash
adb install -r reactor.apk
```

Take a look to **source code** with **jadx**.
We just have a *single activity* (`com.reactor.MainActivity`)
But! This is a *react native* app!
We can see in the code:
```java
public class MainActivity extends ReactActivity {  
    @Override // com.facebook.react.ReactActivity  
    protected String getMainComponentName() {  
        return "Reactor";  
    }  
}
```

We can see that we need to insert a **4 digits PIN**.
Any PIN will give us an broken text. 
May be if we insert the *correct PIN* we **get the flag**?

First, we need look for the **source code**.
Using **apktool** we can *decompile the `.apk` file*
```bash
apktool d reactor.apk
```
Then, inside of the new `reactor` directory, we can see in `asset` directory.
Inside, the `index.android.bundle`.

But this file is like obfuscated. So, you can go to:
https://prettier.io/

Or just, download the code from my website already copied ;)
https://lautarovculic.com/my_files/reactorCode.js

Inside of the JavaScript code, we can see this function searching for some *already known strings*:
```javascript
var o = function () {
    var u = (0, n.useState)(""),
        o = (0, t.default)(u, 2),
        f = o[0],
        c = o[1],
        p = (0, n.useState)(""),
        s = (0, t.default)(p, 2),
        y = s[0],
        v = s[1];
    return n.default.createElement(
        l.ScrollView,
        null,
        n.default.createElement(
            l.Text,
            { style: { fontSize: 45, marginTop: 30, textAlign: "center" } },
            "\u2622\ufe0f Reactor \u2622\ufe0f"
        ),
        n.default.createElement(
            l.Text,
            { style: { padding: 10, fontSize: 18, textAlign: "center" } },
            "Insert the pin to show the reactor codes."
        ),
        n.default.createElement(l.TextInput, {
            style: { height: 40, fontSize: 15, textAlign: "center" },
            placeholder: "PIN",
            keyboardType: "number-pad",
            maxLength: 4,
            onChangeText: function (t) {
                return v(t);
            },
            onSubmitEditing: function (t) {
                c((0, r(d[4]).decrypt)(t.nativeEvent.text)), v("");
            },
            defaultValue: y,
        }),
        n.default.createElement(
            l.Text,
            { style: { padding: 10, fontSize: 18, textAlign: "center" } },
            f
        )
    );
};
e.default = o;
```

We can see the event `onSubmitEditing`
```javascript
onSubmitEditing: function (t) {
    c((0, r(d[4]).decrypt)(t.nativeEvent.text)), v("");
},
```
We need pay attention to this function, the `decrypt`.

This function will take us to:
```javascript
__d(
  function (g, r, _i, a, m, e, d) {
    Object.defineProperty(e, "__esModule", { value: !0 }), (e.default = void 0);
    var t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
      n = {
        encode: function (n) {
          var c,
            h,
            i,
            o,
            A,
            f = [],
            u = "",
            l = "",
            s = 0;
          do {
            (i = (c = n.charCodeAt(s++)) >> 2),
              (o = ((3 & c) << 4) | ((h = n.charCodeAt(s++)) >> 4)),
              (A = ((15 & h) << 2) | ((u = n.charCodeAt(s++)) >> 6)),
              (l = 63 & u),
              isNaN(h) ? (A = l = 64) : isNaN(u) && (l = 64),
              f.push(t.charAt(i) + t.charAt(o) + t.charAt(A) + t.charAt(l)),
              (c = h = u = ""),
              (i = o = A = l = "");
          } while (s < n.length);
          return f.join("");
        },
        encodeFromByteArray: function (n) {
          var c,
            h,
            i,
            o,
            A,
            f = [],
            u = "",
            l = "",
            s = 0;
          do {
            (i = (c = n[s++]) >> 2),
              (o = ((3 & c) << 4) | ((h = n[s++]) >> 4)),
              (A = ((15 & h) << 2) | ((u = n[s++]) >> 6)),
              (l = 63 & u),
              isNaN(h) ? (A = l = 64) : isNaN(u) && (l = 64),
              f.push(t.charAt(i) + t.charAt(o) + t.charAt(A) + t.charAt(l)),
              (c = h = u = ""),
              (i = o = A = l = "");
          } while (s < n.length);
          return f.join("");
        },
        decode: function (n) {
          var c,
            h,
            i,
            o,
            A = "",
            f = "",
            u = "",
            l = 0;
          if (/[^A-Za-z0-9\+\/\=]/g.exec(n))
            throw new Error(
              "There were invalid base64 characters in the input text.\nValid base64 characters are A-Z, a-z, 0-9, '+', '/',and '='\nExpect errors in decoding."
            );
          n = n.replace(/[^A-Za-z0-9\+\/\=]/g, "");
          do {
            (c =
              (t.indexOf(n.charAt(l++)) << 2) |
              ((i = t.indexOf(n.charAt(l++))) >> 4)),
              (h = ((15 & i) << 4) | ((o = t.indexOf(n.charAt(l++))) >> 2)),
              (f = ((3 & o) << 6) | (u = t.indexOf(n.charAt(l++)))),
              (A += String.fromCharCode(c)),
              64 != o && (A += String.fromCharCode(h)),
              64 != u && (A += String.fromCharCode(f)),
              (c = h = f = ""),
              (i = o = u = "");
          } while (l < n.length);
          return A;
        },
      };
    e.default = n;
  },
  401,
  [],
);
```

That confirms that **it's not standard Base64**, although it looks like it.
What they **used is a custom implementation of Base64 in JavaScript**, and the key is in this line:
`var t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";`

**`n`** = "`U1VTUE5aVFVFVXDVEBUFoHDlZcAQYDXApTAg8GA1RaBlQCCVMGB0Q=`" (Base64 encoded ciphertext)
**`decode(n)`** → decode that Base64 string.
**`decrypt(key)`** does: **`XOR(key, decode(n))`**

So, let's brute force that!
We try *all the 4-digit PINs*, and for *each one*:
Extend the PIN to equal the length of the decoded text.
- We XOR byte by by byte.
- If the result is printable (and/or contains a keyword).... it is the correct PIN!

```python
import base64
import string

# Ciphertext
n = "U1VTUE5aVFVXDVEBUFoHDlZcAQYDXApTAg8GA1RaBlQCCVMGB0Q="
decoded = base64.b64decode(n)

def xor_decrypt(key, data):
    # Extend the key until cypher text
    full_key = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytes([ord(full_key[i]) ^ data[i] for i in range(len(data))])

# Brute force
for pin in range(0, 10000):
    pin_str = f"{pin:04d}" # 4 digit PIN
    try:
        result = xor_decrypt(pin_str, decoded)
        result_str = result.decode('utf-8')
        if all(c in string.printable for c in result_str):
            print(f"[+] PIN: {pin_str} → {result_str}")
    except Exception:
        continue
```

You can run the script and pipe with an grep:
```bash
python3 brute.py | grep flag
```

Output:
`[+] PIN: 5927 → flag{cfbb4c6ec59ce316e8d7644ac4c70a12}`

Flag: **`flag{cfbb4c6ec59ce316e8d7644ac4c70a12}`**

I hope you found it useful (: