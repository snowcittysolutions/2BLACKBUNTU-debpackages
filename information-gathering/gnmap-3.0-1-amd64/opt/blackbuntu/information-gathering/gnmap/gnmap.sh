#!/bin/bash
#####################################################################################
# gnmap
#####################################################################################
# Description: Script to parse large amounts of Nmap (.gnmap) exported scan files
#              into multiple plain-text formats for easy analysis.
#####################################################################################

# Global Variables
parsedir=gnmap
portldir=${parsedir}/port-lists
portfdir=${parsedir}/port-files
portmdir=${parsedir}/port-matrix
hostldir=${parsedir}/host-lists
ipsorter='sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4'

# Title Function
func_title(){
  # Clear (For Prettyness)
  clear

  # Print Title
  echo '============================================================================'
  echo ' Gnmap.sh | [Version]: 3.0.1 | [Updated]: 03.05.2013'
  echo '============================================================================'
  echo ' [By]: Michael Wright | [GitHub]: https://github.com/themightyshiv'
  echo '============================================================================'
  echo
}

# Gather Gnmap Files Function
func_gather(){
  echo '[?] Enter The Parent Directory Where Your Gnmap Files Are Located.'
  echo
  read -p '[>] Parent Directory: ' floc
  func_title
  echo '[*] Gathering .gnmap Files'
  find ${floc} -name *.gnmap -exec cp {} . \; >>/dev/null 2>&1
  func_title
  echo "[*] Gathered `ls *.gnmap|wc -l` .gnmap Files"
  echo
  exit 0
}

# Function To Parse .gnmap Files
func_parse(){
  # Check For .gnmap Files Before Parsing
  fcheck=`ls|grep ".gnmap"|wc -l`
  if [ "${fcheck}" -lt '1' ]
  then
    echo '[Failed]: No Gnmap Files Found (*.gnmap).'
    echo
    echo '--[ Possible Fixes ]--'
    echo
    echo '[1]: Run this script with option (-g).'
    echo '[2]: Place this script in a folder with all (*.gnmap) files.'
    echo
    exit 1
  fi

  # Create Parsing Directories If Non-Existent
  echo '[*] Preparing Directories...'
  for d in ${parsedir} ${portldir} ${portfdir} ${portmdir} ${hostldir}
  do
    if [ ! -d ${d} ]
    then
        mkdir ${d}
    fi
  done

  # Build Alive Hosts Lists
  func_title
  echo '[*] Building Alive Hosts Lists...'
  cat *.gnmap|awk '!/#|Status: Down/'|sed -e 's/Host: //g' -e 's/ (.*//g'|${ipsorter} > ${hostldir}/alive-hosts-icmp.txt
  cat *.gnmap|awk '!/#/'|grep "open/"|sed -e 's/Host: //g' -e 's/ (.*//g'|${ipsorter} > ${hostldir}/alive-hosts-open-ports.txt

  # Build TCP Ports List
  func_title
  echo '[*] Building TCP Ports List...'
  cat *.gnmap|grep "Ports:"|sed -e 's/^.*Ports: //g' -e 's;/, ;\n;g'|awk '!/udp|filtered/'|cut -d"/" -f 1|sort -n -u > ${portldir}/tcp-ports-list.txt

  # Build UDP Ports List
  func_title
  echo '[*] Building UDP Ports List...'
  cat *.gnmap|grep "Ports:"|sed -e 's/^.*Ports: //g' -e 's;/, ;\n;g'|awk '!/tcp|filtered/'|cut -d"/" -f 1|sort -n -u > ${portldir}/udp-ports-list.txt

  # Build TCP Port Files
  for i in `cat ${portldir}/tcp-ports-list.txt`
  do
    TCPPORT="$i"
    func_title
    echo '[*] Building TCP Port Files...'
    echo "The Current TCP Port Is: ${TCPPORT}"
    cat *.gnmap|grep " ${TCPPORT}/open/tcp"|sed -e 's/Host: //g' -e 's/ (.*//g'|${ipsorter} > ${portfdir}/port-${TCPPORT}-tcp.txt
  done

  # Build UDP Port Files
  for i in `cat ${portldir}/udp-ports-list.txt`
  do
    UDPPORT="$i"
    func_title
    echo '[*] Building UDP Port Files...'
    echo "The Current UDP Port Is: ${UDPPORT}"
    cat *.gnmap|grep " ${UDPPORT}/open/udp"|sed -e 's/Host: //g' -e 's/ (.*//g'|${ipsorter} > ${portfdir}/port-${UDPPORT}-udp.txt
  done

  # Build TCP Services Matrix
  for i in `cat ${portldir}/tcp-ports-list.txt`
  do
    TCPPORT="$i"
    func_title
    echo '[*] Building TCP Services Matrix...'
    echo "The Current TCP Port Is: ${TCPPORT}"
    cat *.gnmap|grep " ${i}/open/tcp"|sed -e 's/Host: //g' -e 's/ (.*//g' -e "s/^/${i},TCP,/g"|${ipsorter} >> ${portmdir}/tcp-services-matrix.txt
  done

  # Build UDP Services Matrix
  for i in `cat ${portldir}/udp-ports-list.txt`
  do
    UDPPORT="$i"
    func_title
    echo '[*] Building UDP Services Matrix...'
    echo "The Current UDP Port Is: ${UDPPORT}"
    cat *.gnmap|grep " ${i}/open/udp"|sed -e 's/Host: //g' -e 's/ (.*//g' -e "s/^/${i},UDP,/g"|${ipsorter} >> ${portmdir}/udp-services-matrix.txt
  done

  # Remove Empty Files
  func_title
  echo '[*] Removing Empty Files...'
  find ${parsedir} -size 0 -exec rm {} \;

  # Show Complete Message
  func_title
  echo '[*] Parsing Complete.'
  echo
}

# Start Statement
func_title
case ${1} in
  -g|--gather)
    func_gather
    ;;
  -p|--parse)
    func_parse
    ;;
  *)
    echo ' [Usage]...: gnmap [OPTION]'
    echo ' [Options].:'
    echo '             -g | --gather = Gather .gnmap Files'
    echo '             -p | --parse  = Parse .gnmap Files'
    echo
esac
