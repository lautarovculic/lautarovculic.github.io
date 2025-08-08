**Description**: Welcome to the **Android App Security Lab: SQL Injection Challenge**! Dive into the world of cybersecurity with our hands-on lab. This challenge is centered around a fictitious "Food Store" app, highlighting the critical security flaw of SQL Injection (SQLi) within the app's framework.

**Download**: https://lautarovculic.com/my_files/foodStore.apk
**Link**: https://www.mobilehackinglab.com/path-player?courseid=lab-food-store

![[foodStore.png]]

Install it with **ADB**
```bash
adb install -r foodStore.apk
```

Then, let's decompile with **apktool**
```bash
apktool d foodStore.apk
```
Also, let's check the **source code** with **jadx** (GUI version)

When we *launch* the app, we can notice the following message in the login activity
*Please be advised that signing up via the application grants regular user status. For Pro user privileges, kindly contact the administrator*

Inspect the **source code** for understand what this app does.
Looking the source code, I found something interesting about **SQLi** handlers and helpers.

First, in the **Signup** class we can find this code
```java
User newUser = new User(i, obj, obj2, editText2.getText().toString(), false, 1, null);
dbHelper.addUser(newUser);
Toast.makeText(this$0, "User Registered Successfully", 0).show();
return;
```

But this just call the **DBHelper** class. So, the root of this is in the DB class.
Exactly, the **`addUser`** method.
```java
public final void addUser(User user) {
    Intrinsics.checkNotNullParameter(user, "user");
    SQLiteDatabase db = getWritableDatabase();
    byte[] bytes = user.getPassword().getBytes(Charsets.UTF_8);
    Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
    String encodedPassword = Base64.encodeToString(bytes, 0);
    String Username = user.getUsername();
    byte[] bytes2 = user.getAddress().getBytes(Charsets.UTF_8);
    Intrinsics.checkNotNullExpressionValue(bytes2, "this as java.lang.String).getBytes(charset)");
    String encodedAddress = Base64.encodeToString(bytes2, 0);
    String sql = "INSERT INTO users (username, password, address, isPro) VALUES ('" + Username + "', '" + encodedPassword + "', '" + encodedAddress + "', 0)";
    db.execSQL(sql);
    db.close();
}
```

The **structure** of the table is
`username`, `password`, `address`, `isPro`
So, if you pay attention, when we insert an `'` in the **username** field when we'll registered, the app **will crash**.
But, **why this doesn't happen in password and address** field?
This is because the app takes those values and is converted in **base64**.
And the `isPro` is **boolean** (`true` or `false`).

The main difference between **Pro** and **No Pro** is the **credit amount**.
**No Pro**: 100
**Pro**: 10000
You can verify this in **LoginActivity**: `int credit = user.isPro() ? 10000 : 100;`

Retaking the **SQLi vulnerability**, we must understand how the **query** is executed.
Let's use the original query:
```java
String sql = "INSERT INTO users (username, password, address, isPro) VALUES ('" + Username + "', '" + encodedPassword + "', '" + encodedAddress + "', 0)";
```

So, we can try register as user `impro', '', 'address', 1); --`
Where
`impro` -> Username
`',` -> Moving to next argument
`''` -> Password (empty)
`, 'address',` -> Next argument and address
`1` -> Is true (pro)
`); -- -` -> Close query

So, use the *malicious query* and fill the *password* and *address* with any string. Then, login just with *username* (in this case `impro`).

You can see that now you're a **Pro User** and you have `10000` credits!

But, how we can **mitigate** this?
This is **due to incorrect concatenation**.

Using **SQLiteStatement** with **bound parameters** completely eliminates the possibility of injection.
```java
public final void addUser(User user) {
    SQLiteDatabase db = getWritableDatabase();
    String sql = "INSERT INTO users (username, password, address, isPro) VALUES (?, ?, ?, ?)";
    SQLiteStatement stmt = db.compileStatement(sql);

    stmt.bindString(1, user.getUsername());
    stmt.bindString(2, Base64.encodeToString(user.getPassword().getBytes(Charsets.UTF_8), Base64.DEFAULT));
    stmt.bindString(3, Base64.encodeToString(user.getAddress().getBytes(Charsets.UTF_8), Base64.DEFAULT));
    stmt.bindLong(4, 0); // isPro always init as 0

    stmt.executeInsert();
    stmt.close();
    db.close();
}
```

**Validation and Sanitization of Inputs**, even if you use *Prepared Statements*, it is always good to **validate** and **sanitize** the *entries* before they reach the database.
```java
public boolean isValidInput(String input) {
    return input != null && input.matches("^[a-zA-Z0-9_@.]+$");
}
```


I hope you found it useful (: