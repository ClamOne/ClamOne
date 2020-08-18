# ClamOne

An Open Source Linux Frontend to the ClamAV Antivirus Engine. A basic graphical user interface, designed for a Desktop environment, to provide instant feedback when threats are detected on the local system. Features include configuring the clamd daemon directly from the GUI, indication of threats via visual cues as well as notifications, monitoring and updating the virus definitions, monitoring various clam-related event logs and messages, quarantining of detected threats, and visual graphing of antivirus activity.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

In order to run ClamOne, you will need several required packages installed. On a debian-like system run the following:

```
$ sudo add-apt-repository universe
$ sudo apt-get update
$ sudo apt-get -y install clamav clamav-daemon clamdscan libqt5sql5-sqlite libqt5widgets5
```

If you decide to compile the source code,

```
$ lupdate ClamOne.pro
$ lrelease ClamOne.pro
$ qmake
$ make
$ ./ClamOne
```

### Installing

If a package is available for download grab a copy of the latest and run:


```
$ sudo dpkg -i clamone.deb
```

You can then run it with:

```
$ ClamOne
```

## Deployment

This software must be run along with the clamav engine, it requires the engine in order to operate properly

## Built With

* [Qt](https://doc.qt.io/qt-5.9/) - The C++ framework used
* [ClamAV](https://www.clamav.net/) - An open source antivirus engine for detecting trojans, viruses, malware & other malicious threats.
* [libprocps-dev](https://salsa.debian.org/debian/procps/) - A simple interface library to the /proc filesystem
* [zlib](https://zlib.net/) - A massively spiffy yet delicately unobtrusive compression library

## Versioning

We use [GitHub](https://github.com/ClamOne/ClamOne) for versioning. For the releases available, see the [releases on this repository](https://github.com/ClamOne/ClamOne/releases). 

## Authors

* **Lazlo182** - [ClamOne](https://github.com/ClamOne) - [Keybase](https://keybase.io/Lazlo182)

See also the list of [contributors](https://github.com/ClamOne/ClamOne/graphs/contributors) who participated in this project.

## License

This project is licensed under the GNU General Public License v2 - see the [LICENSE.md](https://github.com/ClamOne/ClamOne/blob/master/LICENSE.md) file for details

## Acknowledgments

* sidebar7
* SertDF
* MCorson
