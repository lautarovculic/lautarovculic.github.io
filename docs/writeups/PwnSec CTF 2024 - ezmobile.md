**Description**: Just an ez mobile chall for n00bies.
**Download content**: https://lautarovculic.com/my_files/ezmobile.zip

![[pwnSec_ezmobile1.png]]

Install the **apk** with **ADB**
```bash
adb install -r ezmobile.apk
```

Let's inspect the **source code** with **jadx**.
![[pwnSec_ezmobile2.png]]

And the flag is in the **`res/values/strings.xml`** resources.
We can also paste the **flag decoded** into the app for check the flag.

Flag: **`PWNSEC{w3lp_n07h!ng_Sp3Ci4l_Just_4_Fl4g_!n_7h3_s7r!ng5_xml_f!l3}`**

I hope you found it useful (: