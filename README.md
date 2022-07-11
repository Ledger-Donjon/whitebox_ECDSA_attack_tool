# Automatic attack tool for whitebox ECDSA

This repo contains an automatic attack tool, allowing for the attack of some whitebox ECDSA implementation, with very little to none human interaction.

The tool compiles the provided challenge and tries to inject faults by randomly perturbing one or several faults of the binary file. The faulty values are then exploited by Differential Fault Analysis methods.

It has been used to automatically break most of the challenges of the [WhibOx contest](https://whibox.io/contests/2021/). Note however that some challenges resist to our automatic approach!

For more details about the tool design, please read the associated [blogpost](https://blog.ledger.com/whitebox_ecdsa/).

## How to use?

First of all, you'll need to download the challenges from the WhibOx website:

```shell
python3 download_challenges.py
```

All available sources will be contained in the created directory `challenges`.

Now, you can target any challenge by giving its id number as argument:

```shell
$ python3 pwn_fault.py --only_F --target 3
Target pubkey: 71948E19545103FB435F876DC4A805C380077DA6454A6A3B69DF0F4F96DE768435BF260A31C75C313E13DD8C144F9789F0138DEA7B31BE5B98BA44FD263DB279
main_a
Correct sig1: 9EFC917AAE547F81F3C2043EBD4EA6C7334E7190CD5B460CC4F17C39EC20B44FFC1C1F4398EB08FCD57E42CA6FB1848827D9AC487501FC299BE3E5A3378D954A

main_a
new_output: 9EFC917AAE547F81F3C2043EBD4EA6C7334E7190CD5B460CC4F17C39EC20B44FFC1C1F4398EB08FCD57E42CA6FB1848827D9AC487501FC299BE3E5A3378D954A

FOUND FAULT: ['6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C29616ED39C8C9E9D9F88CCE099CB0A8C1375C7489A9D21EAF7FB41FB46AC9C620CB\n']
trying to recover the key...
Trying -1
Nope...
Trying 31253071056798043433470842980578431346673942427308960093681577454551269345214
Found correct public point: 0x71948e19545103fb435f876dc4a805c380077da6454a6a3b69df0f4f96de7684 0x35bf260a31c75c313e13dd8c144f9789f0138dea7b31be5b98ba44fd263db279
Found private key: 31253071056798043433470842980578431346673942427308960093681577454551269345214
In hex: 0x45189c81eadee03202bfa06eaa15831789f0c76575508a563e1a739ca37b87be
Fault: index=0x165b, value=0xc1
```

The ```-only_F``` option ensures that only the simplest and most efficient attack method is used. It implies a quickest execution time, but some challenges may resist. By disabling it, the tool tries to inject faults into two different binary files.

```shell
$ python3 pwn_fault.py --target 3
Target pubkey: 71948E19545103FB435F876DC4A805C380077DA6454A6A3B69DF0F4F96DE768435BF260A31C75C313E13DD8C144F9789F0138DEA7B31BE5B98BA44FD263DB279
main_a
Correct sig1: 9EFC917AAE547F81F3C2043EBD4EA6C7334E7190CD5B460CC4F17C39EC20B44FFC1C1F4398EB08FCD57E42CA6FB1848827D9AC487501FC299BE3E5A3378D954A

main_b
Correct sig2: 43614468D7A4EE8ACD98E7EF1F6F538535FF1A73FFB689C1A836EE9887BB357350D08448F958EA180AACAAD0D4FA3AF918A83931BEDB7FF75A0F42B44CE16C4E

main_a
new_output: 9EFC917AAE547F81F3C2043EBD4EA6C7334E7190CD5B460CC4F17C39EC20B44FFC1C1F4398EB08FCD57E42CA6FB1848827D9AC487501FC299BE3E5A3378D954A

FOUND FAULT: ['6DC364E78BF0D05E30FBC9482FEFA1F07DB0EEF53D20C54EC429096876B88FABAD9D7D0AC49B110571048AACA1E7FFAEB982A546014056F9E6265E83B54BE7F7\n', '6DC364E78BF0D05E30FBC9482FEFA1F07DB0EEF53D20C54EC429096876B88FABAD9D7D0AC49B110571048AACA1E7FFAEB982A546014056F9E6265E83B54BE7F7\n']
trying to recover the key...
Trying -1
Nope...
Trying 31253071056798043433470842980578431346673942427308960093681577454551269345214
Found correct public point: 0x71948e19545103fb435f876dc4a805c380077da6454a6a3b69df0f4f96de7684 0x35bf260a31c75c313e13dd8c144f9789f0138dea7b31be5b98ba44fd263db279
Found private key: 31253071056798043433470842980578431346673942427308960093681577454551269345214
In hex: 0x45189c81eadee03202bfa06eaa15831789f0c76575508a563e1a739ca37b87be
Fault: index=0x30c5, value=0xa1
```

When the execution is complete, you can find the produced correct and faulty binary files ```main_a``` and ```main_a_faulted.out``` (respectively ```main_b``` and ```main_b_faulted.out```) at the root.
