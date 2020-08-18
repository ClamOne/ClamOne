#!/bin/sh
if [ "$USER" != "root" ]; then
  echo "Needs to be run as root" 1>&2
  exit 1
fi
echo "This Fix will install:"
echo "1) clamav "
echo "2) required Qt components "
echo "3) update clamav virus definitions"
echo "4) DISABLE APPARMOR PROFILES for clamd and freshclam"
echo "   (the ubuntu apparmor profiles cause more problems than they're worth)"
echo "Do you still want to proceed? (Y/n)"
read response
if [ "$response" != "Y" ]; then
  exit 1;
fi
if [ -n "$(which add-apt-repository)" ]; then
  add-apt-repository universe
fi
apt-get update
apt-get -y install clamav clamav-daemon clamdscan libqt5sql5-sqlite libqt5widgets5 libqt5charts5
service clamav-freshclam stop
freshclam
service clamav-freshclam start
if [ ! -e /etc/apparmor.d/disable/usr.sbin.clamd ]; then
  ln -s /etc/apparmor.d/usr.sbin.clamd /etc/apparmor.d/disable/
  apparmor_parser -R /etc/apparmor.d/usr.sbin.clamd
fi
if [ ! -e /etc/apparmor.d/disable/usr.bin.freshclam ]; then
  ln -s /etc/apparmor.d/usr.bin.freshclam /etc/apparmor.d/disable/
  apparmor_parser -R /etc/apparmor.d/usr.bin.freshclam
fi
service clamav-daemon restart

