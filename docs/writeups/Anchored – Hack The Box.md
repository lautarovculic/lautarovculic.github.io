![[anchored1.png]]
**Difficult:** Easy
**Category**: Mobile
**OS**: Android

**Description**: A client asked me to check if I can intercept the https request and get the value of the secret parameter that is passed along with the user’s email. The application is intended to run in a non-rooted device. Can you help me find a way to intercept this value in plain text.

----

Download and extract the **zip** file with the password **hackthebox**.
Inside, we can see a **README.txt** file that say

1. Install this application in an API Level 29 or earlier (i.e. Android 10.0 (Google Play)).
2. Install this application in a non-rooted device (i.e. In Android Studio AVD Manager select an image that includes (Google Play)).

With **Android Studio** configured and the **non-root** deviced working, let’s extract the **apk** with **apktool**
```bash
apktool d Anchored.apk
```

And install with **adb**
```bash
adb install -r Anchored.apk
```

We can see the app
![[anchored2.png]]

Let’s inspect the content of the **Anchored** folder
In the **AndroidManifest.xml** file, we can see
```XML
android:networkSecurityConfig="@xml/network_security_config"
```

Looking the file **network_security_config.xml**
```XML
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">anchored.com</domain>
        <trust-anchors>
            <certificates src="@raw/certificate" />
        </trust-anchors>
    </domain-config>
</network-security-config>
```

We can see the trusted certificates, that is in **/Anchored/raw/certificate**
This certificate is for trust in **anchored.com**
```bash
.rw-r--r-- lautaro lautaro 1.3 KB Mon May 27 06:30:11 2024 󰌆 certificate.pem
```

We need intercept the **traffic** and, for it, we need install the **Burp** cert
And, reading about Documentation
`https://developer.android.com/privacy-and-security/security-config`

If we include
```XML
<certificates src="user" />
```

In the **network_security_config.xml** file, this will **trust in any cert that the user install in the device**.

Then, add the line to the code
```XML
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">anchored.com</domain>
        <trust-anchors>
		        <certificates src="user" />
            <certificates src="@raw/certificate" />
        </trust-anchors>
    </domain-config>
</network-security-config>
```

Now we need recompile the application with **apktool**
```bash
apktool b Anchored
```

And
```bash
cd Anchored/dist
```

It’s time for gen a **key**
```bash
keytool -genkey -keystore lautaro.keystore -validity 1000 -alias lautaro
```

Now we need sign the **apk**
```bash
jarsigner -keystore lautaro.keystore -verbose Anchored.apk lautaro
```

Now we need remove the **apk** previously installed
![[anchored3.png]]

And **install the new apk**
```bash
adb install -r Anchored.apk
```

Now it’s time of install **Burpsuite cert**
Regenerate and export a new cert
![[anchored4.png]]

Select in **DER format**
![[anchored5.png]]

And save the cert
![[anchored6.png]]

Now we need upload the cert to the **emulator**
```bash
adb push cert-der.crt /sdcard/Download/
```

Go to **Downloads** on **Files** app
![[anchored7.png]]

And install the cert
![[anchored8.png]]

Now for intercept the traffic, we need know our **ip** address with **ifconfig**
My “attacker” ip is 192.168.18.44
Then, In Android **configuration** in **extended controls** panel, we need set a **manual proxy**.

Follow this steps
![[anchored9.png]]

The **proxy status** must be “**success**”.
Now, run the app and put the email address with **burpsuite intercepting traffic**

And we get the flag
![[anchored10.png]]

Flag: **HTB{UnTrUst3d_C3rT1f1C4T3s}**

I hope you found it useful (: