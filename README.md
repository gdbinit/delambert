Delambert

An IDA plugin to deobfuscate strings from The Lamberts macOS malware sample  
af7c395426649c57e44eac0bb6c6a109ac649763065ff5b2b23db71839bac655
 
24/08/2021  
Pedro Vilaça - reverser@put.as - https://reverse.put.as

Public domain code, do whatever you want, just give credits if you use any of this :P

Build:

Change the `Makefile` paths and build. It will install to `~/.idapro/plugins` folder.

Only macOS supported and tested with IDA 7.6 SP1.

Usage:

Installs a right click menu item on disassembly window.  
You can execute the plugin on the `LEA` instruction that loads the obfuscated string:
```
__text:000098DB 8D 93 43 85 02 00   lea     edx, (byte_31500 - 8FBDh)[ebx] ; output_buf
__text:000098E1 8D 83 49 3E 02 00   lea     eax, (unk_2CE06 - 8FBDh)[ebx] ; obfuscated string
__text:000098E7 E8 B2 F5 FF FF      call    fg_deobfuscate_string4
```

or just go to `__cstring` section and execute it on the beginning of the encrypted string.  

It will add a comment with the deobfuscated string.

Easy to tweak it to rename the variable for easier disassembly reference.

Have fun,  
fG!
