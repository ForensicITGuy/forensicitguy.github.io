---
title: "When Local Password Resets Aren't Local"
date: 2020-01-09T22:07:01-06:00
draft: false
tags: 
    - Windows
    - ActiveDirectory
    - DomainControllers
    - LocalAccounts
    - Administrators
---

## When You Reset a Domain Administrator Instead of Local

During an IR engagement, one of my colleagues identified malicious activity where an adversary reset the password for a local administrator account. While this reset would gain the adversary access to the local administrator account, it might not have warranted an emergency. That is, until we noticed that the password reset occurred on a domain controller.

## Are There Local Accounts on Domain Controllers?

Well, that gets complicated. Security pros and IT generalists are usually aware of SAM account databases on Windows systems. These databases contain the credentials needed for user logons when no domain connections are present. In the absence of Active Directory, such as in workgroup or home network scenarios, the Windows systems will use the SAM account database to authenticate users. In some cases, users may also choose to logon with a local account in enterprise environments, authenticating from the SAM database instead of the domain controller. 

Most Windows systems follow this same pattern, unless they are promoted to Active Directory domain controllers. Once this happens, the promoted DC will stop using the local SAM database for its own everyday authentication, instead it uses the Active Directory database stored in NTDS.dit. In addition, the "local" groups for the DC will be defined by the AD Built-In groups. If the DC is the first of a domain, the contents of the SAM account database are migrated into the new domain's NTDS.dit database. If the DC is an addition to an existing domain, it will receive a replica of the NTDS.dit database to authenticate from.

During the promotion of a domain controller you may also notice that the process requires you to set a Directory Services Restore Mode password. Once you have promoted the domain controller this account will be the only one stored within the local SAM database and it will not be available for use unless you boot into DSRM mode on the DC for recovery.

## Does This Really Matter?

It absolutely matters when investigating password resets and assigning permissions within an Active Directory domain.

Consider these commands:

```
net user Administrator Password123
```

If this command executes on a non-domain controller system, it will reset the local Administrator account's password (in the SAM database) to `Password123`. On a domain controller, it will reset the **_domain's_** Administrator account in NTDS.dit instead. This implies that whoever resets this password will have Administrator access for the entire Active Directory domain and all systems therein rather than just a single system.

This also implies that any malware that achieves use of the SYSTEM account on a domain controller will be able to escalate to domain privileges as the SYSTEM account will be able to reset user account passwords on the DC.

```
net user Joffrey
```

If this command executes on a non-DC system, it will add a local user by the name of `Joffrey` to the SAM database. On a DC, it will add a domain user by the same name to NTDS.dit. This is important because performing this action on a DC may circumvent your account creation processes unintentionally.

```
net localgroup Administrators /add WESTEROS\Jorah.Mormont
```

If this command executes on a non-DC system it will add Jorah's account to the local Administrators group, entitling him to manage a single computer system. If the command executes on a DC system, Jorah's account will be added to the Built-In Administrators group in Active Directory. This would entitle Jorah to make changes to Active Directory's NTDS.dit database, Group Policy Objects, AD Sites, and also allow administrative access on all computers across the domain. This can get very bad very quickly.

## Taking Action

Be vigilent when performing operations on accounts from a domain controller's command line. Remember that your "local" changes likely aren't local if they occur on a DC.

## Sources
- [Technet](https://social.technet.microsoft.com/Forums/exchange/en-US/2f120e62-52a9-4001-b8e0-15a897f28b7e/is-there-any-possible-to-create-a-local-account-on-domain-controller-not-domain-account?forum=winserverDS)
- [Microsoft](https://docs.microsoft.com/en-us/windows/win32/secmgmt/built-in-and-account-domains?redirectedfrom=MSDN#computers-that-are-domain-controllers)