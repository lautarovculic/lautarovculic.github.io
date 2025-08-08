**Description**
This is a simple apk, Could you find the flag?

For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

For download the **APK**
https://lautarovculic.com/my_files/simple.apk

![[simpleApk1.png]]

Install it with **adb**
```bash
adb install -r simple.apk
```

We can see a **text edit** and an **button**.
Let's decompile the **apk** with **apktool**
```bash
apktool d simple.apk
```
The **package name** is `easyre.sjl.gossip.easyre`

Let's inspect the **source code** with **jadx**.
There are an activity called **EasyRe**
This have this method **init** when the app is launched
```java
public void init() {  
        try {  
            InputStream fin = getResources().openRawResource(C0175R.raw.flag);  
            int length = fin.available();  
            byte[] buffer = new byte[length];  
            fin.read(buffer);  
            FileOutputStream fout = openFileOutput("flag.txt", 0);  
            fout.write(buffer);  
            fin.close();  
            fout.close();  
        } catch (IOException e) {  
            e.printStackTrace();  
        }  
    }
```
In the **onCreate** method, we can see that the **init()** is called.
The previous code, create a **flag.txt** file in our device with the flag content.

And this we can confirm because we can see the **onClick** method that is executed when we press the **check** button
```java
public void onClick(View view) {  
        String flag = "";  
        try {  
            FileInputStream fin = openFileInput("flag.txt");  
            int length = fin.available();  
            byte[] buffer = new byte[length];  
            fin.read(buffer);  
            flag = EncodingUtils.getString(buffer, "UTF-8");  
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
        if (flag.equals(this.et1.getText().toString())) {  
            Toast.makeText(getApplicationContext(), "That's the flag!", 0).show();  
        } else {  
            Toast.makeText(getApplicationContext(), "0ops!That's wrong!", 0).show();  
        }  
    }
```

So, just run this **adb** command for get the flag.
The flag is stored in `/data/data/<packageName>`
We get the flag running
```bash
adb shell "cat /data/data/easyre.sjl.gossip.easyre/files/flag.txt"
```

Output: `0ctf{Too_Simple_Sometimes_Naive!!!}`
![[simpleApk2.png]]


I hope you found it useful (: