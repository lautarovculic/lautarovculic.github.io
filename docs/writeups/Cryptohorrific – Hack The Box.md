![[cryptomb1.png]]
**Difficult:** Medium
**Category**: Mobile
**OS**: iOS

**Description**: Secure coding is the keystone of the application security!

----

After downloading the compressed file and decompressing it, we will have a folder where inside we find the files we need:
![[cryptomb2.png]]
The hackthebox file, is the main file of the program that contains the binary files.
The **.plist** file is a list that contains details about the app and author.
This is for gather information when you search an App in the App Store.

The **challenge.plist** have some interesting:
![[cryptomb3.png]]

This must be an base64 encrypted text.
```bash
Tq+CWzQS0wYzs2rJ+GNrPLP6qekDbwze6fIeRRwBK2WXHOhba7WR2OGNUFKoAvyW7njTCMlQzlwIRdJvaP2iYQ==
```
So it’s source code time.
I recommend use IDA for that:

[https://hex-rays.com/](https://hex-rays.com/)
![[cryptomb4.png]]
We load the hackthebox program to our IDA and let’s inspect that.

Here we have a insteresting function: **_CCCrypt**
![[cryptomb5.png]]
Following to **CCCrypt_ptr** we can see that jmp. So, navigate to CCCrypt_ptr and:

We can see between **__cfstring** some interesting things:
```bash
__cfstring:0000000100003128 dq offset aFlag ; "flag”
```
```bash
__cfstring:0000000100003108 dq offset aPlist ; "plist”
```
```bash
__cfstring:00000001000030E8 dq offset aChallenge ; "challenge”
```
```bash
__cfstring:00000001000030C8 dq offset aQftjwnzq4t7wZC ; "QfTjWnZq4t7w!z%C”
```
```bash
__cfstring:00000001000030A8 dq offset aADGKapdsgvky ; "!A%D*G-KaPdSgVkY”
```

![[cryptomb6.png]]
Following, for example: **aADGKapdsgvky**

We are redirect to:
![[cryptomb7.png]]

And may be this is the key and IV of an **AES encryption**. Let’s check:
```bash
!A%D*G-KaPdSgVkY
```
```bash
Tq+CWzQS0wYzs2rJ+GNrPLP6qekDbwze6fIeRRwBK2WXHOhba7WR2OGNUFKoAvyW7njTCMlQzlwIRdJvaP2iYQ==
```
So with these values, we can go to this online tool for decrypt:
[https://www.devglan.com/online-tools/aes-encryption-decryption](https://www.devglan.com/online-tools/aes-encryption-decryption)

And here is, the flag:
![[cryptomb8.png]]
Decode to Plain Text and you will get the flag.

I hope you found it useful (: