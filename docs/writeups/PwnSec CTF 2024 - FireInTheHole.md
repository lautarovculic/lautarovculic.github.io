**Description**: Great job, Mark! You encrypted the files, inserted them into the mobile application, and then forgot how to decrypt them. Seriously? Now, we have to figure out your mess. Well done! And by the way... YOU'RE FIRED!
**Download content**: https://lautarovculic.com/my_files/fire-in-the-hole.zip

![[pwnSec_fireinthehole1.png]]

Install the **apk** with **ADB**
```bash
adb install -r FireInTheHole.apk
```

We can see some wallpaper screen.
Let's check the **source code** with **jadx** (GUI version)
But before, let's **decompile** it with **apktool**
```bash
apktool d FireInTheHole.apk
```

We can see in the **MainActivity** are a **frida-detection**. But we don't use frida today.
Just taking around code and *resources*, check the **`strings.xml`** file.
There are a **firebase** url
![[pwnSec_fireinthehole2.png]]

Which using the classic **`/.json`** we can list the *database*.
In Firebase, when you access the **Realtime Database** through a *URL*, you can see the **structure of the data in the database** through a URL, you can see the structure of the data in **JSON format**. The URL usually ends in *`.json`*, which indicates that you are requesting the data in JSON format.

Or just we can use **curl**
```bash
curl -X GET "https://fire-in-the-hole-92c34-default-rtdb.firebaseio.com/.json"
```
Output:
**`KEY`**: `BwKZIxIyEkMyRK+uvyrDxA==`
**`IV`**: `WFLjr63DwQ4GrDNAMLvBsw==`
Both in **base64**.

In the **Decrypter** class, we can see the following code in `onCreate()` method
```java
public void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    EdgeToEdge.enable(this);
    setContentView(R.layout.activity_decrypter);
    
    StringBuilder sb = new StringBuilder();
    C0605g b2 = C0605g.b();
    this.key = b2;
    this.key_databaseReference = b2.e("Key");
    
    C0605g b3 = C0605g.b();
    this.IV = b3;
    this.IV_databaseReference = b3.e("IV");
    
    try {
        InputStream open = getAssets().open("one.txt");
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(open));
        
        while (true) {
            String readLine = bufferedReader.readLine();
            if (readLine == null) {
                bufferedReader.close();
                open.close();
                decrypt(sb.toString().getBytes(), Base64.decode(getkey(), 0), Base64.decode(getIV(), 0));
                return;
            }
            sb.append(readLine);
        }
    } catch (IOException e2) {
        throw new RuntimeException(e2);
    }
}
```

We can see that try **decrypt** the `one.txt` file. Which can be found in the **assets** directory that **apktool** drop.
Copy the content of `one.txt` or just *upload the file* in **cyberchef** (https://cyberchef.org/)
But, trying all `.txt` files I don't have the flag, until I upload `Four.txt`
![[pwnSec_fireinthehole3.png]]

Flag: **`PWNSEC{Y0uR_F!r3_L4ck5_d!sciplin3}`**

I hope you found it useful (: