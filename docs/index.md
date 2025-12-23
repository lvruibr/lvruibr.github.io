## [IDMHound](https://lvruibr.github.io/idmhound)

Pentesting and auditing FreeIPA/Red Hat Identity Management environments - the Linux counterpart of Active Directory - often proved to be a tedious task. The lack of proper visualization makes it hard to quickly identify overly privileged accounts, leaving potential attack paths hidden in plain sight.

**IDMHound** addresses this blind spot. 

It is a BloodHound collector designed to graph identities and relationships within a FreeIPA/IdM realm, helping pentesters and IAM auditors quickly understand privilege structures and risks.

📖 Blog post: [https://lvruibr.github.io/idmhound](https://lvruibr.github.io/idmhound)

💻 Repository: [https://github.com/lvruibr/idmhound](https://github.com/lvruibr/idmhound)

***

## [Dumping tickets in Kerberos Cache Manager (and detecting it)](https://lvruibr.github.io/kcmdump)

Keberos tickets have been interesting targets for adversaries looking to perform lateral movements. On Linux machine, the ease of obtaining tickets and detecting such abuses greatly depends on the credential cache used.

In the case of Kerberos Cache Manager (KCM), the tickets can be retrieved by leveraging the KCM socket. With low privileges, only one's own tickets will be dumped, but as root all tickets can be retrieved.

From a defensive perspective, dumping tickets through the KCM socket is relatively challenging to detect. Nonetheless, a few interesting detection opportunities exist.

📖 Blog post: [https://lvruibr.github.io/kcmdump](https://lvruibr.github.io/kcmdump)

***

