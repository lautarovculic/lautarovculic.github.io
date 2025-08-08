![[investigator1.png]]
**Difficult:** Medium
**Category**: Mobile
**OS**: Android

**Description**: In one of the mobile forensics investigations we encountered, our agent gave us these files and told us that their owner using one password for almost everything. Can you extract the flag from the secret messages?

---

Download the **.zip** file and extract the content with the **hackthebox** password.

Inside, there are a folder and an **.ab** file
```bash
drwx------ lautaro lautaro 4.0 KB Wed Sep 14 22:37:00 2022  system
.rw-r--r-- lautaro lautaro 6.5 MB Wed Sep 14 22:23:36 2022  backup.ab
```

An **.ab** file is a **backup** for **Android**.

We can use **adb** for restore it
```bash
adb restore backup.ab
```

But we need a **password**
![[investigator2.png]]

_Note: You need **android 5.0**_
Let’s check the **system** folder.

We have some interesting files:
```bash
.rw-r--r-- lautaro lautaro  20 B  Wed Sep 14 22:33:47 2022 󰌆 gesture.key
.rw-r--r-- lautaro lautaro  20 KB Wed Sep 14 22:34:34 2022  locksettings.db
.rw-r--r-- lautaro lautaro  72 B  Wed Sep 14 22:33:47 2022 󰌆 password.key
.rw-r--r-- lautaro lautaro 228 B  Wed Sep 14 22:33:47 2022  device_policies.xml
```

The **password.key** have this content
```bash
E135432C47718760B2FD7AF5CFF7A7608A926ED6B5515B7D0DB34FF62F5C388A88B1665C
```

And in **locksettings.db** we can found
```bash
6|lockscreen.password_salt|0|6675990079707233028
```
Where **6675990079707233028** is a salt.

In **devices_policies.xml**
```XML
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<policies setup-complete="true">
<active-password quality="262144" length="5" uppercase="0" lowercase="5" letters="5" numeric="0" symbols="0" nonletter="0" />
</policies>
```

We can conclude that the **password** for restore the **backup file** is 5 lowercase letters of **5 digits**.
The **gesture.key** is a file for set/get the **gesture patron**, but we don’t need that in this escenario.
Normally, in the **backup** files on **Android 5.0**, the **password.key** file are a combination of **SHA1** and **MD5** uppercased.
The **first** segment is an **SHA1** and the **rest is MD5**.

**SHA1**
```bash
e135432c47718760b2fd7af5cff7a7608a926ed6
```

**MD5**
```bash
b5515b7d0db34ff62f5c388a88b1665c
```

Then, now for **get the real salt** we need convert the **decimal value** (6675990079707233028) to **hex**.
```python
def decimal_to_hex(decimal):
    hex_value = hex(decimal)[2:]
    return hex_value

salt_decimal = 6675990079707233028

salt_hex = decimal_to_hex(salt_decimal)

print("Salt (hex):", salt_hex)
```

Output:
```bash
5ca5e19b48fb3b04
```

Then we can crack with **hashcat** this **sha1:salt** **hash**
```bash
e135432c47718760b2fd7af5cff7a7608a926ed6:5ca5e19b48fb3b04
```

```bash
hashcat -m 110 hash.txt -a3 "?l?l?l?l?l"
```

**-m 110** = sha1($pass.$salt)
**-a3** = bruteforce
**“?l?l?l?l?l”** = 5 chars lowercase.

Hash cracked:
```bash
e135432c47718760b2fd7af5cff7a7608a926ed6:5ca5e19b48fb3b04:dycpr
```
Then, the password for extract the **backup.ab** file is **dycpr**

We can use this tool
`https://sourceforge.net/projects/android-backup-processor/`

For extract the **backup content** to our **directory** and **work in our desktop environmet**.
```bash
java -jar abp.jar unpack backup.ab backupOutput.tar dycpr
```

The **abp.jar** file is in
```bash
/android-backup-processor/executable
```

Now let’s work with the **.tar** file
We get **two folders**, **shared** and **apps**.
We can see that WhatsApp is in the **folder shared**
```bash
/shared/0/WhatsApp/Databases
```

And there are an file: **msgstore.db.crypt14**
This is the **WhatsApp** database cypher in **crypt14**.
We need a key, that is stored in
```bash
/apps/com.whatsapp/f/key
```
I found this tool

You can install it with **pip**
```bash
pip install git+https://github.com/ElDavoo/wa-crypt-tools
```

And then
```bash
wadecrypt key msgstore.db.crypt14 msgstore.db
```

With **sqlite3** we can dump the tables.
```bash
sqlite> .tables
```

We can see **message** table
```bash
sqlite> select * from message;
1|-1|0|-1||||||||||-1||||||0
15|2|1|CEB7EDD170A2A49DDD78622E8C0F1EA7|0|6|0|0||0|0|1663204120140|0|-1|7||0|0|0|15
16|2|1|4ED16892285DD5E9B810E2FAF0257660|0|13|0|0||0|0|1663204155269|0|1663204155000|0|Hi|0|0|0|16
17|2|0|6B88D4F12763BBA948C75EB675606226|0|0|0|0||0|0|1663204161000|1663204162013|-1|0|Error(403):
Incorrect identifier, try again...|0|0|0|17
18|2|1|7E9ADD9D0376ACE6A4D59D149EB1038E|0|13|0|0||0|0|1663204210685|0|1663204210000|0|Hi0o0|0|0|0|18
19|2|0|1D9BE5BB583B2D3B147056F1B41BFD11|0|0|0|0||0|0|1663204216000|1663204216493|-1|0|OK:
Enter your password|0|0|0|19
20|2|1|10097BEF5E4BA51A9BE64A47DC1B6ABE|0|13|0|0||0|0|1663204577005|0|1663204577000|0|dycpr|0|0|0|20
21|2|0|C7947CD8CA0646E40A7B24CFB50B4C8F|0|0|0|0||0|0|1663204586000|1663204586692|-1|0|OK:
Here is your secret
HTB{M0b1l3_*************_<3}|0|0|0|21
sqlite>
```
And we get the flag

I hope you found it useful (: