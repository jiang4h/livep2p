#!/bin/bash

# crontab -e
# */1 * * * * /opt/livep2p/checkrun.sh

PROG="livep2p"
STARTCMD="./livep2p"
LogFile="./checkrun.log"

DIR=`dirname $0`
cd $DIR
DIR=`pwd`

PERMINUTE=1
FULLCMD=${DIR}/$(basename $0)

ulimit -c unlimited
	
PID=`ps -ef | grep $PROG | grep -v grep | awk '{print $2}'`
if test "aa$PID" == "aa"; then
	RUN=0
else
	RUN=1
fi

if [ $RUN -eq 0 ]; then
    echo "" >> $LogFile 
    echo "----------------------------------------" >> $LogFile 
    echo $(date +"%y-%m-%d %H:%M:%S") found system crashed. >> $LogFile 
    echo "Now starting..." >> $LogFile 

    $STARTCMD &> /dev/null

    #PID=`pidof $PROG`
    PID=`ps -ef | grep $PROG | grep -v grep | awk '{print $2}'`
    if test "x$PID" != "x"; then
        echo "livep2p service has been started, PID=$NPID!" >> $LogFile
    else
        echo "livep2p failed to start! PID=$NPID" >> $LogFile
    fi
fi

JOBN=$(crontab -l | grep -c "^\*/${PERMINUTE} \* \* \* \* ${FULLCMD}$")
if [ ${JOBN} -eq 0 ]; then
    TMPF="/tmp/cron492"$RANDOM
    if [ -f ${TMPF} ]; then
        /bin/rm -f ${TMPF}
    fi
    echo "*/${PERMINUTE} * * * * ${FULLCMD}" >> ${TMPF}
    crontab -l | grep -v "${FULLCMD}" >> ${TMPF}
    crontab ${TMPF}
    /bin/rm -f ${TMPF}
fi

