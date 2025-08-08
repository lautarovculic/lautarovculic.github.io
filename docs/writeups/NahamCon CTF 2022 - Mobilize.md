**Description**: Autobots. ROLLL OUTT!!!!!!

**Download**: https://lautarovculic.com/my_files/mobilize.apk

![[nahamcon2022_mobilize1.png]]

Install the **APK** file with **ADB**
```bash
adb install -r mobilize.apk
```

This app doesn't nothing haha.
![[nahamcon2022_mobilize2.png]]

Just, extract the app with **jadx** or just **unzip**.
Inside of `res/values/strings.xml` you can find the **flag**.

Or just
```bash
unzip mobilize.apk && strings resources.arsc | grep flag
```

Flag: **`flag{e2e7fd4a43e93ea679d38561fa982682}`**

I hope you found it useful (: