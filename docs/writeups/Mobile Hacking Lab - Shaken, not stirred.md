**Description**: A spy has infiltrated a private intelligence company in Paris and was able to steal sensitive documents. Luckily, he is not a tech geek and could easily be tracked down by law enforcement 24 hours after infiltration. His mobile phone could be seized. However, it was damaged on purpose by the suspect and only a small fragment of user artifacts could be retrieved. The key for decrypting the flag could not be extracted. Are you able to find a way to decrypt it?

**Link**: https://www.mobilehackinglab.com/course/lab-shaken-not-stirred

![[mhl-shaken1.png]]

### Recon
Unzip the `.zip` file downloaded from course and let's take a tour into directories and files.

We were given a partial dump of a *Samsung device* with multiple artifacts (`databases`, `notes`, `images`, `audio`, `SMemo`, etc.). The mission was to **decrypt the `flag_mhc.enc` file** located in the **`SecureFolder`** directory.

Let's start analyzing the *databases*.

The first database is **`BrowserHistory.db`** located at:

- `Browser/data/com.sec.android.app.sbrowser/databases`

```bash
SQLite version 3.44.4 2025-02-19 00:18:53
Enter ".help" for usage hints.
sqlite> .headers on
sqlite> .tables
history
sqlite> select * from history;
_id|url|title|visit_time|is_bookmarked
1|https://www.google.com/search?q=What+is+the+best+country+without+extradition|Google Search: What is the best country without extradition|1753930518358|0
2|https://www.google.com/search?q=Is+aes+encryption+secure|Google Search: Is aes encryption secure|1754015178358|0
3|https://www.google.com/search?q=Can+aes+be+broken|Google Search: Can aes be broken|1753988898358|0
4|https://www.google.com/search?q=What+are+best+aes+modes|Google Search: What are best aes modes|1753968018358|0
5|https://www.google.com/search?q=What+should+i+do+to+hide+data+in+an+android+phone|Google Search: What should i do to hide data in an android phone|1753969218358|0
6|https://www.google.com/search?q=Can+someone+find+data+within+an+encrypted+container+or+file|Google Search: Can someone find data within an encrypted container or file|1754003778358|0
7|https://www.google.com/search?q=Is+it+possible+to+detect+the+encryption+type|Google Search: Is it possible to detect the encryption type|1753960278358|0
8|https://www.google.com/search?q=Where+do+i+need+to+store+sensitive+files|Google Search: Where do i need to store sensitive files|1753945578358|0
9|https://www.google.com/search?q=What+is+the+best+sensitive+file+storage+method|Google Search: What is the best sensitive file storage method|1753877478358|0
10|https://www.google.com/search?q=Can+cloud+storage+providers+be+trusted|Google Search: Can cloud storage providers be trusted|1753874478358|0
11|https://www.google.com/search?q=Does+VPN+help+communicate+securely|Google Search: Does VPN help communicate securely|1753975218358|0
12|https://www.google.com/search?q=Top+10+best+VPNs+for+2025|Google Search: Top 10 best VPNs for 2025|1754022918358|0
sqlite>
```

We can see a *lot of search* about **AES encryption** and storing *sensitive data*.

*Nothing useful here*. So, let's see the next database file, which is **`samsung_notes.db`** located at `db` directory.
```bash
SQLite version 3.44.4 2025-02-19 00:18:53
Enter ".help" for usage hints.
sqlite> .headers on
sqlite> .tables
notes
sqlite> select * from notes;
id|title|content
1|Reminder|I have to meet Elian tomorrow
2|Travel|Flight to Paris 11:45 for 226 Euro
3|Luggage|Key on separate bag
4|Random Note|The quick brown fox jumps over the lazy dog.
5|Math|Pi is approximately 3.14159
6|Key Derivation|10000 Iterations
7|Idea|Building the future requires better questions.
8|Draft|Not all who wander are lost, some just like maps.
9|Reminder|key 32 bit
sqlite>
```

Here we can found *a lot of useful information*:

- **Key Derivation** -> 10000 Iterations -> This may indicate the use of `PBKDF2`.

- **Reminder** -> key 32 bit.

The rest of the information can be misleading and distract us from the challenge.

I saw a `.wav` file in `Audio` directory, with the name `awful noise.wav`.

After play this audio, Immediately notice that is **Morse code**.

We can *decode this code* in:

- https://morsecode.world/international/decoder/audio-decoder-adaptive.html

The content that have is: **`PBKDF2 WITH SHA256`**

This confirms the **KDF algorithm**.

**Definition**:
*A Key Derivation Function (KDF) is a cryptographic algorithm that transforms a primary secret, like a password or master key, into one or more secure cryptographic keys.
KDFs strengthen weak inputs (such as passwords) and extract, expand, and format them into keys of the correct length and format, often using techniques like salting, hashing, and iterations to increase computational cost and resist brute force attacks.*

Let's now take a look at the **images** in `Images` directory:

Quickly, I noticed that there is an image named `passphr1.png` and also `2.png`, `3.png`, `4.png` and `5.png` which **are QR codes that can be scanned**.

You can use your *mobile phone*, but I prefer using **`zbar`** tool suite.
```bash
zbarimg passphr1.png
```
Output: **`red`**

If we use the same command for `2`, `3`, `4`, `5` `.png` files, we can put together the **passphrase**.

**KEY**: **`red34DuckMango!#2022++`**

But we have more images in the directory that we must analyze.

I use https://georgeom.net/StegOnline tool for image inspection, and I noticed that the **`School.png`** image contains something in the bit planes.

This can been seen clearly in the *Red 0*:
![[mhl-shaken2.png]]

So, let's use **`zsteg`** tool for extract all the data.
```bash
zsteg -a School.png | head
```
Output:
```bash
imagedata           .. text: "\r\r(*.@DJ"
chunk:0:IHDR        .. file: unicos (cray) executable
b1,r,lsb,xy         .. text: "GxBY2Mzc3MhIQ=="
b1,rgb,lsb,xy       .. text: "VDNybTFuNGxBY2Mzc3MhIQ=="
b2,r,msb,xy         .. text: ["U" repeated 107 times]
[...]
[...]
[...]
```

We got **`VDNybTFuNGxBY2Mzc3MhIQ==`** text content, which *decoding the content* is **`T3rm1n4lAcc3ss!!`**

On the other hand, I saw that the image `connect.png` contains some *credentials* to connect via Wi-Fi
```bash
zbarimg connect.png
```
Output:
```bash
WIFI:T:WPA;S:TP-Link_CTF_NET;P:ctfStrongPass2025;;
```
Password: **`ctfStrongPass2025;;`** (not useful for the challenge).

But, an useful image for inspect, is `beautiful_thing.png`, that contains a **user comment**.

Using the famous **exiftool** we can got the information:
```bash
exiftool beautiful_thing.png
```
Output:
```bash
[...]
[...]
Green Tone Reproduction Curve   : (Binary data 64 bytes, use -b option to extract)
Blue Tone Reproduction Curve    : (Binary data 64 bytes, use -b option to extract)
User Comment                    : For3ns1cQ
Exif Byte Order                 : Little-endian (Intel, II)
Orientation                     : Horizontal (normal)
[...]
[...]
```

We got the **`For3ns1cQ`** word!

*We already have enough information anyway, so given the time I've "wasted" investigating the rest of the information and clues the challenge gave, I'll decide to document the use of the outguess tool.*

Let's look at the contents of the **`SMemo`** directory.

We see that there are two `.snb` files inside.

**SNB files are primarily associated with Samsung's outdated S Note application**, serving as archives for notes containing text, images, audio, and video.

This are like `.zip` files, so, you can *unzip* the content and take a look.

Inside, we have *To do sunday* and *Gmail* directory.

In both, we have an `snb_thumbnailimage_001.jpg` file.

The content of the images are:

- **`Gmail`** -> Gmail Elos ivani

- **`To do sunday`** -> A list in To-Do format.
	- Installing anti forensic
	- Picture hiding
	- Gonna ask Jonathan

*I fell into this rabbit hole*, and after extensive analysis with steganography tools, I discovered the **outguess** tool.

- https://github.com/resurrecting-open-source-projects/outguess

I knew that for this I would have to **find a password** and thus extract information that would not be useful to solve the challenge.

After trying *many of the combinations and variations of the information above*, I realized that perhaps the words listed above might be helpful.

Since the contents of the "*Gmail*" directory contained **ivani**, that's the only reason I laughed that the *IV would be inside the binary*.

The password for:

- `SMemo/Gmail/snote/media/snb_thumbnailimage_001.jpg` -> password: **`ivani`**

- `SMemo/To do sunday/snote/media/snb_thumbnailimage_001.jpg` -> password: **`anti`**.

We can use *outguess* for extract the binary inside:
```bash
outguess -k 'ivani' -r snb_thumbnailimage_001.jpg gmail.bin || true
```
And
```bash
outguess -k 'anti' -r snb_thumbnailimage_001.jpg sunday.bin || true
```
I even tried **nybbles swapping** ([REF](https://www.geeksforgeeks.org/dsa/swap-two-nibbles-byte/)) with all the results we've had.

But none of that worked.
### Solution
I already had everything I needed to **decrypt the flag with a script**.
```python
from pathlib import Path
from hashlib import pbkdf2_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64

CT = Path("SecureFolder/flag_mhc.enc").read_bytes()
IV = base64.b64decode("VDNybTFuNGxBY2Mzc3MhIQ==")
P  = b"red34DuckMango!#2022++"
S  = b"For3ns1cQ"

KEY  = pbkdf2_hmac("sha256", P, S, 10000, 32)
dec  = Cipher(algorithms.AES(KEY), modes.CBC(IV)).decryptor().update(CT) + Cipher(algorithms.AES(KEY), modes.CBC(IV)).decryptor().finalize()
unp  = padding.PKCS7(128).unpadder()
pt   = unp.update(dec) + unp.finalize()
print(pt.decode())
```
Output:
```bash
MHC{mobile_4n6_1s_N0T_TH4t_H4Rd_h30d8fn48nfwuhf32f892fh23urh328}
```

**Flag**: **`MHC{mobile_4n6_1s_N0T_TH4t_H4Rd}`**

I hope you found it useful (:
