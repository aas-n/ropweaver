<h1 align="center">
  <br>
  <a href="[https://github.com/aas-n/ropweaver/]"><img src="https://i.ibb.co/rvTHTNg/chaine-4.png" alt="Ropweaver"></a>
  <br>
  Ropweaver
  <br>
</h1>

<h4 align="center">Linking gadgets, weaving exploits.</h4>
<p align="center">
  <a href="https://github.com/aas-n/ropweaver">
    <img src="https://img.shields.io/badge/Release-0.1-yellow.svg">
  </a>
  <a href="https://twitter.com/aas_s3curity">
    <img src="https://img.shields.io/badge/Twitter-aas-blue.svg">
  </a>
  <a href="">
    <img src="https://img.shields.io/badge/python-3.x-red">
  </a>
</p>


### Index
| Title        | Description   |
| ------------- |:-------------|
| [About](#about)  | Brief Description about the tool |
| [Installation](#installation)  | Installation and Requirements |
| [Usage](#usage)  | Ropweaver usage |
| [Semantic](#semantic)  | About semantic |
| [Examples](#examples)  | Examples |
| [Changelog](#changelog)  | Ropweaver changelog |
| [Disclaimer](#disclaimer)  | Disclaimer |


### About 
ropweaver is a straightforward, unpretentious tool developed as part of my OSED certification journey. It classifies and chains ROP gadgets in Windows binaries, supporting semantic-based searches, bad byte filtering, and organized gadget categorization.

### Installation
```
git clone https://github.com/aas-n/ropweaver.git
pip install argparse
```

### Usage
```
python ropweaver.py <filename> [options]
Options
<filename>: R++ file output containing the list of gadgets.
-b, --bad-bytes: Specify bad bytes to exclude from the gadgets, e.g., '00 0a 0b 0d'.
-c, --no-color: Disable colored output.
-l, --limit: Limit the number of gadgets displayed per category.
-s, --semantic: Search for gadgets matching a specific semantic instruction, e.g., 'eax <- ecx' or '[edi] <- ecx'.
-a, --virtualaddress: The virtual address of the module in hexadecimal (-a '0x10000000').
-v, --debug: Enable verbose output for debugging.
```

### Semantic
Semantic allows you to find and chain gadgets based on pseudo code.
```
-s 'eax <- ecx'           # mov eax, ecx
-s '[eax] <- ecx'         # mov [eax], ecx or mov dword ptr [eax], ecx
-s 'eax <- [ecx]'         # mov eax, [ecx] or mov eax, dword ptr [ecx]
-s 'eax <-> ecx'          # xchg eax, ecx
-s 'eax + ecx'            # add eax, ecx
-s 'eax - ecx'            # sub eax, ecx
-s 'eax <- 0'             # xor eax, eax;
-s 'eax <- ecx + offset   # offset two complement; pop ecx; ret; sub eax, ecx; ret;
-s 'eax++'                # inc eax;
-s 'eax--'                # dec eax;
-s 'neg eax'              # neg eax;
```

### Examples
<h3 align="center">
  <a href="https://github.com/aas-n/ropweaver"><img src="https://i.ibb.co/pPms7hB/categorize.png" alt="Ropweaver"></a>
</h3>

<h3 align="center">
  <a href="https://github.com/aas-n/ropweaver"><img src="https://i.ibb.co/LkjTJDG/re.png" alt="Ropweaver"></a>
</h3>

### Changelog
```
Version 0.1
=============
[ ] add advanced chaining
[ ] add variations to categories
[x] add baseAddress option
[x] support windows r++ outputs
[x] support linux r++ outputs
[x] add basic chaining
[x] add semantic eax <- ecx + offset and eax <- ecx offset
[x] add gadget categorization
[x] add gadget filtering
[x] add no-color to make grep easier
[x] add semantic mode
[x] add debug mode
```

### Disclaimer
This tool was developed as part of my OSED certification journey and is intended for educational and research purposes only. Use it responsibly.
