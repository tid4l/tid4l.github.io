---
title: You SPN Me Round - Abusing SPNs in Windows Domain Environments
date: 2022-12-2 15:30:00 -0600
categories: [Active Directory, Kerberos]
tags: [spn, active directory, windows, kerberos, persistence, discovery, reconnaissance]     # TAG names should always be lowercase
---

A Service Principal Name, or SPN, is a key feature of Window Kerberos authentication. Because they exist in most Windows domain environments, they have potential for abuse during a red team engagement. In this post, I'd like to highlight a few of these uses. But first, let's briefly go over what a SPN is.

## What is an SPN?

According to the [Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names):

> A service principal name (SPN) is a unique identifier of a service instance. SPNs are used by Kerberos authentication to associate a service instance with a service logon account. This allows a client application to request that the service authenticate an account even if the client does not have the account name.

Abstract definitions aside, SPNs are essentially used to identify what services will utilize the chosen account's security context. For instance, one may use a user account when running a SQL server service. By assigning this account an SPN, it is now considered a service account. An example would look like MSSQLSvc/SQL-Svr-01.target.local. There is a ton of info out there on this topic.

## Kerberoasting

### Overview

The first topic we'll explore is the one most folks in this space might be familiar with: Kerberoasting. This post-exploitation technique is used to harvest credentials within an Active Directory environment. In this scenario, an attacker can begin the authentication process through Kerberos and receive the password hash for the service account. Mitre classifies this technique as [T1558.003](https://attack.mitre.org/techniques/T1558/003/).

### Attack steps

To execute this technique, one must:

1. Have access to a domain user and session within the Active Directory environment.

2. Request a service ticket from the Kerberos ticket granting service (TGS).

3. Receive a service ticket from the Kerberos key distribution center (KDS).

4. Pull the ticket offline and crack the password hash for the service account. The hashed password is contained within the service ticket.

    > These hashes cannot be used in a pass-the-hash attack, unlike Windows New Technology LAN Manager (NTLM) hashes.
    {: .prompt-info }

5. Use the service account and plaintext password to access network resources.

There are a multitude of available tools to perform this technique, but we'll cover it with Ghostpack's [Rubeus](https://github.com/GhostPack/Rubeus).

### Rubeus Usage

Using Rubeus to accomplish this technique is pretty straightforward. With access to a domain account on a domain-connected host, we can run rebeus to request a service ticket. 

```powershell
> Rubeus.exe kerberoast
```

If there are any abusable service accounts, this command will execute the previously described technique and output the hash from the ticket. We can also specify the output file: `/outfile:`.

Additionally, because Rubeus is written in C#, we can execute it in memory through a C2 framework like Cobalt Strike, reducing OPSEC risks. In Cobalt Strike:

```console
beacon> execute-assembly /root/Rubeus.exe kerberoast
```

Rubeus is an awesome tool with a ton more features, this is but one aspect of it. With the newly acquired hash, we can use a tool like [John](https://www.openwall.com/john/) to crack it (hopefully; see mitigations).

### Mitigations

The best way to prevent this technique is a strong password policy, especially for service accounts. The longer and more complex password, the less likely it can be cracked. It's especially important to protect service accounts that may have special or elevated privileges.

## SPN Persistence

### Overview

Another interesting, maybe somewhat less know technique is using SPNs for persistence. This relatively straightforward technique involves adding an SPN to an account that we'd like to maintain access to, even if the password gets changed. If access to the account is lost, the account can then be kerberoasted to receive the new password hash, which can (maybe) be cracked.

### Usage

We can run the following command to add a SPN to the `targeted.user` account.

```powershell
> setspn -a MSSQLSvc/SQL-Svr-01.target.local targeted.user
```

We can verify that this worked by running the following command:

```powershell
> get-aduser targeted.user -prop serviceprincipalname
[...]
serviceprincipalname : {MSSQLSvc/SQL-Svr-01.target.local}
[...]
```

If the password gets changed, we can simply use targeted kerberoasting as described earlier to receive a password hash and regain access. 

Interestingly, if we have access to a privileged user that has the ability to modify SPNs, we can add an SPN to a more privileged administrator, then kerberoast it to receive the administrator's password hash. This can serve as a means to elevate privilege. 

### Mitigation

Like before, a strong password can help mitigate this technique. Auditing accounts with SPNs may also reveal suspicious service accounts or SPNs in places they don't belong. 

## SPN Scanning

### Overview

Finally, let's touch on a technique where we can use SPNs to discover services and hosts within the network. This is not as in-depth as the previous techniques but has the potential to reveal significant information about the network in a relatively stealthy way. 

### Usage

With user access, we can run a simple powershell command to output all the SPNs within the domain.

```powershell
> setspn -Q */*
```

Of note, the astericks in this command are wildcards, which we can replace with key terms to narrow our results. Some of built-in SPNs that are recognized include dns, http, iisadmin, and rpc, to name a few. These can replace the first wildcard. For example, the command can be formatted as `setspn -Q http/*`.

By querying the domain directly, we can reveal services and hosts, even ports. We can discover services like databases, web server instances, and much more. This can alleviate the reliance on less OPSEC-friendly host and port scans.


## Final Thoughts

Ultimately, these are not novel techniques, however, they all take advantage of the built-in service prinicipal name feature within an Active Directory environment. Large domains are almost guaranteed to utilize SPNs to some capacity. Although they serve a valuable purpose within the domain, they are readily available for abuse. Defenders should take extra care with SPNs as they consider risks associated with certain domain functionalities.

Hopefully, this post effectively summarizes SPNs and how a red team may utilize them more effectively in an engagement. 

### Further Reading

- [Kerberoasting Attacks](https://www.crowdstrike.com/cybersecurity-101/kerberoasting/)

- [SPN Scanning – Service Discovery without Network Port Scanning](https://adsecurity.org/?p=1508)

- [Sneaky Persistence Active Directory Trick #18: Dropping SPNs on Admin Accounts for Later Kerberoasting](https://adsecurity.org/?p=3466)