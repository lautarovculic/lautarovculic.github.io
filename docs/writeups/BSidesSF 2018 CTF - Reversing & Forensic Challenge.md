Download **content**: https://lautarovculic.com/my_files/bsides_2018.zip

![[bsides2018_1.png]]

Install the **APK** with **ADB**
```bash
adb install -r passwordVault.apk
```

But first let's take a look at the file `passwordVaultDiskImage`.
We can see that is
`passwordVaultDiskImage: XZ compressed data, checksum CRC64`

We just need **extract** the file.
```bash
7z x passwordVaultDiskImage
```
Try extract the new file again, there are a `pew` folder.

This will drop a **.fat** file, we can use **fatcat** tool for inspect the content.
```bash
fatcat passwordVaultDiskImage\~ -l /pew
```
```bash
Listing path /pew
Directory cluster: 3
d 4/4/2018 00:03:14  ./ (.)                                             c=3
d 4/4/2018 00:03:14  ../ (..)                                           c=0
d 4/4/2018 00:03:14  .git/ (GIT~1)                                      c=4
```

But also we can search for **deleted files**
```bash
fatcat passwordVaultDiskImage\~ -l /pew -d
```
```bash
Listing path /pew
Directory cluster: 3
d 4/4/2018 00:03:14  ./ (.)                                             c=3
d 4/4/2018 00:03:14  ../ (..)                                           c=0
d 4/4/2018 00:03:14  .git/ (GIT~1)                                      c=4
f 4/4/2018 00:03:52  password (ASSWORD)                                 c=445 s=12 (12B) d
```

Here's a *password* file.
We can read this with
```bash
fatcat passwordVaultDiskImage\~ -r /pew/password
```
And the password is `I</3Porgis!`

Let's take a look to `.git` content, first place
```bash
git checkout -f master
```
Then, looking for all commits (with `git log`) I found in the commit `55bb1750d984691c154aa7b8a4877e2e6ac3e055` (*Temp test file*) a `vault.db`.

The `.db` file is in the new directories that git was dropped `app/testArtifact`.
![[bsides2018_2.png]]
We can see an "**flag**" which is `J0yGSBs5EaApkR67G/iZjK12kkTk1XBMzWdy7P58iqGUDfLjLlGOZf/nryFXQqBh`.

Come back to the **source code** of the a.pp. Inspect this with **jadx** (GUI version).
The **package name** is `ctf.com.passwordvault` and there are **three activities**. But, we will focus on some *piece of code*.
This code are present in the **`CryptoUtilities`** class
```java
public SecretKeySpec getKey(String password) throws Exception {
    byte[] salt = "SampleSalt".getBytes();
    char[] passwordArray = password.toCharArray();
    SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    KeySpec ks = new PBEKeySpec(passwordArray, salt, 1000, 128);
    SecretKey secretKey = secretKeyFactory.generateSecret(ks);
    SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
    return keySpec;
}

public String encrypt(String plaintext) throws Exception {
    byte[] plaintextBytes = plaintext.getBytes();
    this.cipher.init(1, this.key);
    byte[] ciphertext = this.cipher.doFinal(plaintextBytes);
    Log.d("Status", Base64.encodeToString(ciphertext, 2));
    return Base64.encodeToString(ciphertext, 2);
}

public String decrypt(String ciphertext) throws Exception {
    byte[] ciphertextBytes = Base64.decode(ciphertext.getBytes(), 2);
    Log.d("Status", ciphertextBytes.toString());
    this.cipher.init(2, this.key);
    byte[] plaintext = this.cipher.doFinal(ciphertextBytes);
    return new String(plaintext, "UTF-8");
}
```

We can recreate a **script in frida** that **simulates the decryption** of the flag since *we have the password*.
```javascript
Java.perform(function () {
    var CryptoUtilities = Java.use("ctf.com.passwordvault.CryptoUtilities");
    var instance = CryptoUtilities.$new("I</3Porgis!");
    var decryptedFlag = instance.decrypt("J0yGSBs5EaApkR67G/iZjK12kkTk1XBMzWdy7P58iqGUDfLjLlGOZf/nryFXQqBh");
    console.log("[*] Flag: " + decryptedFlag);
});
```

And we have the following output:
```bash
Attaching...
[*] Flag desencriptada: CashInTheSafeIDontFeelThePressure
```

Flag: **`CashInTheSafeIDontFeelThePressure`**

I hope you found it useful (: