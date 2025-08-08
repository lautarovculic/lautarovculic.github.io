![[h1tmsts.png]]
**Flags:** 2
**Difficulty:** Easy
**Category:** Mobile

-----
First, I recommend that you read the following post I wrote for Intercepting Android app traffic using Burpsuite.

At the end of the post, there is the second flag
But first, _I want to clarify something_.

In this Writeups it is possible to get both flags with **two commands**, which seems to me a bad practice.
Because **there is an intentional way**, which I will explain to get the second flag.

Let’s go

## Flag 1/2
When we start the challenge on the platform, it will take us to a URL.
A sign will appear saying that the application is being built.
We wait a few seconds and then we will see that we can download the APK file.
Once downloaded, we move it to a separate directory to be able to work in peace.

```bash
mv /home/user/Downloads/thermostat.apk .
```
![[h1tmsts1.png]]

With **apktool** we are going to **unzip the APK file**.
```bash
apktool d thermostat.apk
```
![[h1tmsts2.png]]

Now, we get the folder with the APK content inside.
![[h1tmsts3.png]]

Considering the format of the **^FLAG^** in Hacker101, we can try to **execute a command** that will bring us all the strings that **match those characters**.
```bash
grep -ir '\^FLAG\^' thermostat \
| awk -F':' '{print $2}' \
| sed 's/^[[:space:]]*//' \
| sed 's/const-string v0, //'
```

![[h1tmsts4.png]]

And we get both flags. But!!
This method is just for the first flag.
Now, we will found the second flag in the intended way.

## Flag 2/2
So, the intended way is intercepting the traffic that the App send to the Hacker101 URL (Where we download the App).
Remember read the post that I wrote about how to intercept the Android app traffic with Burpsuite.
We need send the app to our **Genymotion Android device**, we can do that with

```bash
python3 -m http.server 8050
```
And, with the firefox browser, **download the .apk**

![[h1tmsts5.png]]

![[h1tmsts6.png]]

Download the .apk and **install it**.
With **burpsuite running**, and the **proxy** (explained in the blog post) **setup**, we can **intercept the traffic** (run the App with the interceptor listening):

![[h1tmsts7.png]]
And in the header (**X-Flag**) we found the intended flag.

I hope you found it useful (: