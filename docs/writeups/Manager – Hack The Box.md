![[manager1.png]]
**Difficult:** Easy
**Category**: Mobile
**OS**: Android

**Description**: A client asked me to perform security assessment on this password management application. Can you help me?

---

Download, and extract the **.zip** file with the password **hackthebox**, and, **Start the Instance**.
In my case is: **94.237.54.233:56388**
There are a **README.txt** file that say

1. Install this application in an API Level 29 or earlier (i.e. Android 10.0 (Google APIs)).
2. In order to connect to the server when first running the application, insert the IP and PORT that you are provided in the description.

Extract the content with **apktool**
```bash
apktool d Manager.apk
```

And install the **apk** with **adb**
```bash
adb install -r Manager.apk
```

We will see the message that need the **IP Server** and **Port**
![[manager2.png]]

Let’s connect
And there are a **login** and **register** menu.
Go to register a **new user**.
I try Sign Up as **admin** but says that are **Taken**

Idk if there are a part of the challenge or another **HTB User** create this account, but I’ll keep this in mind.
![[manager3.png]]

Here we can see some **info** about the **app**.
There are a **ID**, **user**, **pass (we can change)**, and **role**.
Then, **intercepting the request of the UPDATE button**

I change the username **lautaro** to **admin**
![[manager4.png]]

And the **password** for **admin** has **updated (IDOR).**

Then, **log in** as **admin** we can found the flag
![[manager5.png]]

I hope you found it useful (: