# LedgerNanoSHack

It is a try to reverse engineer the Ledger Nano S that is the best existing Bitcoin (and other cryptocurrencies) Hardware Wallet in the market.

*Ledger Live.exe* is the desktop application to manage Ledger Nano S. It is an Electron application based on NodeJs and uses [node-hid](https://github.com/node-hid/node-hid) library to access HID devices.

On the other hand, Ledger Nano S has a *Secure Element* to store the master seed and private keys. This secure element is a smart card chip that communicates using APDU messages.

For reverse engineering, Wireshark is enough to monitor USB messages and extract transferred APDUs, but if I want to modify them and do a *Man-In-The-Middle* attack, I need developing some hacking code, and this project is that!

This code uses [EasyHook](https://easyhook.github.io/) to inject two fake functions into LedgerLive.exe address space, including:

* [CreateFileA](https://docs.microsoft.com/en-us/windows/desktop/api/fileapi/nf-fileapi-createfilea)
* [WriteFile](https://docs.microsoft.com/en-us/windows/desktop/api/fileapi/nf-fileapi-writefile)

CreateFileA opens the HID device and WriteFile sends USB messages including APDU to the device. In this hack, I get the HID device handle by injecting my code into CreateFileA function and modify transferred APDUs by injecting my code into WriteFile function.

As a result, I could intercept APDUs between LedgerLive.exe and *Ledger Nano S* device and modify them as MITM attack.

The code is organized as follows:

* hookDLL project: includes functions' hooks and hack code.
* injectorApp project: a console application that finds LedgerLive.exe files and injects function hooks into them.

Because LedgeLive.exe is a NodeJs app, it runs inside that and creates four processes. So, injectorApp finds all and injects hack code to them, but only the correct one is hacked by checking the FilePath in the CreateFileA call.

You can use this project to do some experiment with Ledger Nano S and maybe other USB Hardware Wallets.