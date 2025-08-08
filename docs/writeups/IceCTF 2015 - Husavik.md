**Description**: This handy Android App is supposed to display the flag, but it's not working!
**Note**: For this challenge, we need install some things into our Android 5.1 device with Genymotion.
For example, an **ARM Translator**.
https://github.com/m9rco/Genymotion_ARM_Translation

Download **APK**: https://lautarovculic.com/my_files/husavik.apk

![[iceCTF1.png]]

Install the **apk** with **adb**
```bash
adb install -r husavik.apk
```

Then, decompile it with **apktool**
```bash
apktool d husavik.apk
```

We can see inspecting the **source code** with **jadx** (GUI version)
That in the **MainActivity** we don't have any interesting..
We just can see that some **Threads** of **c** and **b** class are **started**.

In **RedHerring** we don't have any of our interest.
So, we can see in the **run** method of **b** class
```java
public void run() {  
        try {  
            Socket socket = new Socket("127.0.0.1", 6464);  
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());  
            objectOutputStream.writeObject("ZmxhZ193YWl0X3dhc250X2l0X2RhbHZpawo=");  
            objectOutputStream.close();  
            socket.close();  
        } catch (IOException e) {  
            e.printStackTrace();  
        }  
    }
```

As in the **c** class
```java
public void run() {  
        try {  
            this.f4a.f2c = new ServerSocket(6464);  
            while (true) {  
                this.f4a.f2c.accept();  
            }  
        } catch (IOException e) {  
            e.printStackTrace();  
        }  
    }
```

The same thing, a **Socket Connection** that send the **string** `ZmxhZ193YWl0X3dhc250X2l0X2RhbHZpawo=`
Which if we decode in **base64** the string we get the flag
```bash
echo 'ZmxhZ193YWl0X3dhc250X2l0X2RhbHZpawo=' | base64 -d
```
`flag_wait_wasnt_it_dalvik`

But, here we don't make the things of this way.
So, let's get the **flag** of the **correct way** that is via a **socket** connection.

Let's modify the **b** class, the **run** method. Changing the `127.0.0.1` IP address for our **LAN** IP, in this case, our laptop or PC.
In my case, is `192.168.1.6`.
So, let's search the code in the **smali** file

```bash
grep -r "127.0.0.1" husavik/smali/ -n
```

We have the sentence in
`husavik/smali/tf/icec/husavik/b.smali:36:    const-string v3, "127.0.0.1"`

In the **line** 36 of **b.smali** file.
Change the **IP**, and save the file.

So now, **rebuild the apk** with **apktool**
```bash
apktool b husavik
```

Generate a **key**
```bash
keytool -genkey -v -keystore name.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias alias
```

**Sign** the apk
```bash
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore name.keystore husavik/dist/husavik.apk alias
```

Then, **uninstall** the old apk in our device and **install** the recently signed.
```bash
adb install -r husavik/dist/husavik.apk
```

Let's run an **listener** in our **6464** port with **nc**
```bash
nc -lvp 6464
```

Launch the app and press the button
```bash
nc -lvp 6464
Connection from 192.168.1.6:51098
�t$ZmxhZ193YWl0X3dhc250X2l0X2RhbHZpawo=%
```
We will receive the **flag** via the socket.


I hope you found it useful (: