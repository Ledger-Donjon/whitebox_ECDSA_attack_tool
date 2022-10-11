# Automatic attack tool for whitebox ECDSA

This repo contains an automatic attack tool, allowing for the attack of some whitebox ECDSA implementation, with very little to none human interaction.

The tool compiles the provided challenge and tries to inject faults by randomly perturbing one or several faults of the binary file. The faulty values are then exploited by Differential Fault Analysis methods.

It has been used to automatically break most of the challenges of the [WhibOx contest](https://whibox.io/contests/2021/). Note however that some challenges resist to our automatic approach!

Tool works alongside with the `ecdsattack` package. This package is standalone and can be easily reused in a different project.

For more details about the tool design, please read the associated [blogpost](https://blog.ledger.com/whitebox_ecdsa/).

## How to use?

First, install the `ecdsattack` package:

```shell
pip install .
```

Install GCC 10. Every submission must be written in C accepted by GCC 10.2.0, according to the [WhibOx rules](https://whibox.io/contests/2021/rules). This is why our attack framework also uses this compiler.

On Debian and Ubuntu based distributions, run:

```shell
sudo apt install gcc-10
```

Then, you need to download the challenges from the WhibOx website.
The `download_challenges.py` script automatically downloads the required files:

```shell
cd whibox
python3 download_challenges.py
```

All available sources will be stored in the `challenges` directory.

Now, you can target any challenge by giving its id number as an argument:

```shell
$ python3 attack_challenge.py 3
Target pubkey: (51373825986355774071250980279620467994040880475046330500810086649905043895940,24310311305488748994553138095599191243412933863929305440484464503786399707769)
Got original signatures
Found fault: [Signature(h=77194726158210796949047323339125271902179989777093709359638389338608753093290, r=51261857506776367647170974185543587743399745698476691298914904042177902976601, s=24034990606478394525403416946129616596586010172124072163530054669774869469257), Signature(h=84914198774031876643952055673037799092397988754803080295602228272469628402619, r=14550751080734615811966333159702574286792132474439442617840429198988393190538, s=103645674120494530263794094172624223700881526969124523449288297793523532913381)]
Found correct public point: (51373825986355774071250980279620467994040880475046330500810086649905043895940,24310311305488748994553138095599191243412933863929305440484464503786399707769)
Found private key: 31253071056798043433470842980578431346673942427308960093681577454551269345214
In hex: 0x45189c81eadee03202bfa06eaa15831789f0c76575508a563e1a739ca37b87be
Fault: index=0x16ea, value=0x6b
# crashes =  7
# faults without effect =  31
```

The ```--fast``` option ensures that only the simplest and most efficient attack method is used. It implies a quickest execution time, but some challenges may resist. By disabling it, the tool tries to inject faults into two different binary files.

```shell
$ python3 attack_challenge.py --fast 3
Target pubkey: (51373825986355774071250980279620467994040880475046330500810086649905043895940,24310311305488748994553138095599191243412933863929305440484464503786399707769)
Got original signatures
Found fault: [Signature(h=77194726158210796949047323339125271902179989777093709359638389338608753093290, r=49098583567513067215186017367485795504455019334892761483083891015802167749698, s=23655982380257869798946273962635685699073675603598634877083025295238220904608)]
Found correct public point: (51373825986355774071250980279620467994040880475046330500810086649905043895940,24310311305488748994553138095599191243412933863929305440484464503786399707769)
Found private key: 31253071056798043433470842980578431346673942427308960093681577454551269345214
In hex: 0x45189c81eadee03202bfa06eaa15831789f0c76575508a563e1a739ca37b87be
Fault: index=0x18f6, value=0xd2
# crashes =  1
# faults without effect =  12
```

When the execution is complete, you can find the correct and faulted binary files that produced the signatures, ```main_a``` and ```main_a_faulted``` (respectively ```main_b``` and ```main_b_faulted```) at the root.
