#!/bin/bash
#=================================================================================================
# Name: Joe Nguyen
# Description:
#     This script is used to read the input Pcap and change all the current PCAP subnets with
#     the current subnet of the tcpreplay ethernet interface .
# Notes:
# Need to install the following package:
#     ubuntu: apt-get install ipcalc
#=================================================================================================
PORT="eth1"
LOOP=1
INPUT="none"
LOGDIR=/opt/uploads

function getPcapSubnet {
    TEMP=$1
    SUBNET=$2
    STRING=`cat $TEMP | awk '{ print $5 ;}' | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'`    
    declare -A ARRAY
    for ELE in $STRING
    do
	#    echo "IP=$ELE"
	IFS='.' read -r -a LIST <<< "$ELE"
	LEN=${LIST[0]}
	if [ "${ARRAY[LIST[0]]}" == "" ]
	then
	    ARRAY[${LIST[0]}]=1 
	else
	    count=${ARRAY[${LIST[0]}]}
	    ARRAY[${LIST[0]}]=$(( count + 1 )) 
	fi
    done
    #echo ${ARRAY[@]}
    orgsub=""
    for k in "${!ARRAY[@]}"
    do
#	echo "Key=$k"
	if [ "$k" == "255" ]
	then
#	    echo "Skip 255"
	    continue
	fi

	if [ "$orgsub" == "" ]
	then
	    orgsub="$k.0.0.0/8:$SUBNET"
	else
	    orgsub=$orgsub",""$k.0.0.0/8:$SUBNET"
	fi
    done
    echo $orgsub
    return 0
}

function usage () {
    echo "$0 -p(ort) $1 -i(nputfile) $2 -l(ogdir) $3 -L(oop) $4"
    echo " example: $0 -p $1 -i input.pcap -l $3 -L $4"
}
while getopts "hp:l:i:L:" opt
do
    echo " OPT=$opt -- $OPTARG "
    case $opt in
        p) PORT=$OPTARG  ; echo "PORT=$PORT "  ;;
        l) LOGDIR=$OPTARG  ; echo "LOGDIR=$LOGDIR "         ;;
        L) LOOP=$OPTARG  ; echo "LOOP=$LOOP "         ;;
        i) INPUT=$OPTARG  ; echo "Inputfile=$INPUT"         ;;
        h) usage $PORT $INPUT $LOGDIR $LOOP; exit 0;;
        :) echo "Option $opt require an argument " >&2 ; usage $PORT $INPUT $LOGDIR $LOOP  ; exit 1;;
        [?]) echo "Invalid option: -$OPTARG" >&2 ; usage $PORT $INPUT $LOGDIR $LOOP; exit 1;;
    esac
done
if [ ! -d $LOGDIR ]
then
    rc=`mkdir -p $LOGDIR`
    if [ "$?" == "1" ]
    then
	echo "could not make directory $LOGDIR"
	exit 1
    fi   
fi
if [ "$INPUT" == "none" ]
then
    echo "Please enter file name"
    usage  $PORT $INPUT 
    exit 1
fi
#whoami
BNAME="OUTPUT_"`basename $INPUT`
TEMP=$LOGDIR/temp.log
#ssh -i /tmp/tester.pem tester@localhost "sudo /usr/sbin/tcpdump -r $INPUT" > $TEMP
sudo /usr/sbin/tcpdump -r $INPUT > $TEMP
subnet=`netstat -r  | grep -v -E "default|link-local"| grep $PORT | awk '{print $1;}' `
NM=`netstat -r  | grep -v -E "default|link-local"| grep $PORT | awk '{print $3;}' `
netmask=`ipcalc -c $subnet/$NM | grep Netmask | awk '{print $4}'`
subtitute=$(getPcapSubnet  $TEMP "$subnet/$netmask" )
#echo "NEW STRING=$subtitute"
echo "--------------------------"
echo "$0 -p(ort) $PORT -i(nputfile) $INPUT  -l(ogdir) $LOGDIR -L(oop) $LOOP"
echo "Subnet of $PORT: $subnet"
echo "---------------------------"
echo "==>tcprewrite --pnat=$subtitute --infile=$INPUT --outfile=${LOGDIR}/${BNAME} --skipbroadcast"
tcprewrite --pnat=$subtitute --infile=$INPUT --outfile=${LOGDIR}/${BNAME} --skipbroadcast
echo "==>tcpreplay --timer=gtod --loop=$LOOP --intf1=$PORT ${LOGDIR}/${BNAME}"
#ssh -i /tmp/tester.pem tester@localhost "sudo  /usr/bin/tcpreplay --loop=$LOOP --intf1=$PORT ${LOGDIR}/${BNAME}"
sudo  /usr/bin/tcpreplay --timer=gtod --loop=$LOOP --intf1=$PORT ${LOGDIR}/${BNAME}
echo " ----  End of tcpreplay  --- "
