#!/usr/bin/python
#--------------------------------------------------------------------------------------------------
# Name: Joe Nguyen
# Date: 03/19/2014
# Description: This tool is used to test the brute force access to any host through repeating login
#---------------------------------------------------------------------------------------------------
#from __future__ import division
import re
import time
import string
import random
import types
import math
import os,sys,signal
import subprocess
import httplib
import urllib
import json
import socket
import binascii
import struct
#from ftplib import FTP
import ftplib


#import optparse
from optparse import OptionParser
from optparse import Option
DGAINT= 30 # Send good DGA DNS packets for every 30 bad DGA packets
PASS=0
FAIL=1
RUNNING = 11
EXIT = 12
RESOLVPATH="/etc/"
SUDO=" "
curr_path= os.getcwd()
scriptpath, scriptname = os.path.split(sys.argv[0])
(SCNAME,junk)= scriptname.split('.')
SCNAME = "template_"+SCNAME +".json"
#------------
#Port Scan
#-----------
DROP="DROP"
REJECT="REJECT"
OPEN="OPEN"
ABUSE="abuse"
PSCAN="pscan"
TCP="tcp"
UDP="udp"
FRAGIP="frag"


CON_END="CX_END"
NOPASSWD="nopassword"
USER="root"
#------------
# Post infected
#-----------



#---------------
# function
#---------------
class MultiOptions(Option):
    ACTIONS= Option.ACTIONS + ("extend",)
    STORE_ACTIONS = Option.STORE_ACTIONS + ("extend",)
    TYPED_ACTIONS = Option.TYPED_ACTIONS + ("extend",)
    ALWAYS_TYPED_ACTIONS = Option.ALWAYS_TYPED_ACTIONS + ("extend",)


def take_action ( self, action,dest,opt,value,values,parser):
        if ( action == "extend" ):
            #listvalue = values.split(",")
            listvalue=value
            values.ensure_value(dest,[]).append(listvalue)
        else:
            Option.take_action(self, action, dest, opt, value, values , parser)


def main(ptrTbl,cPath,sName) :
    instruction = "usage: %prog [options] arg"
    progversion="%prog 1.0"
    list = scriptname.split('.');
    defaultName= cPath+'/'+list [0] +".log"
    INTRO="The %prog utility is used to generate bruteforce login to either (ssh|ftp|rdp|vnc|http) \n ( Examples: python %prog -m ftp -i template_bruteforce.json -s 10.0.101.1 -o 10 -p  testhost1.qa.blackhat -l ./junk -f 2 -x 1 -a PASS )"
    optparser= OptionParser(option_class=MultiOptions,usage=instruction,version=progversion,description=INTRO)

    optparser.add_option ("-b", action="store_true", default=False,dest="bypass", help="bypass scan pkt generator")
    optparser.add_option ("-c", default=NOPASSWD, dest="password", help="password, default="+NOPASSWD)
    optparser.add_option ("-e", "--ethif", default="eth1",dest="testif", help="Test interface, default(eth1)")
    optparser.add_option ("-f", default = 1 , dest="iteration", help="Number Of Iteration -- default = 1 and 0 forever")
    optparser.add_option ("-l", "--path", dest="wpath", help=" log directory path ( Default:"+cPath+")")
    optparser.add_option ("-i", "--input", default=None,dest="input", help="input json filename")
    optparser.add_option ("-o", "--srcrange", default=1, dest="srcrange", help="Source Range : 1")
    optparser.add_option ("-p", "--slaveip",default=None, dest="slaveip", help="Slave Host Ip  ")
    optparser.add_option ("-s", "--srcip",default=None, dest="srcip", help="Source Host Ip default: source host IP ")
    optparser.add_option ("-m", "--select",default="ftp", dest="select", help="select which type of login (ssh|ftp|rdp|vnc|http)")
    optparser.add_option ("-t", action="store_true", dest="tempgen", help="Generate a json template file")
    optparser.add_option ("-v", "--rwait",default =0, dest="rwait", help="random of waiting in seconds between 2 consecutive scan packets ( Default: 0 )")
    optparser.add_option ("-u", default=USER, dest="user", help="user default="+USER)
    optparser.add_option ("-r", "--result", dest="resultfile", help="resultfile filename(default:"+defaultName+")")
    optparser.add_option ("-w", "--wait", default =0, dest="twait", help="wait in seconds between 2 consecutive scan packets ( Default: no wait(0) )")
    optparser.add_option ("-x", default = 0 , dest="verbose", help="Turn on debugging trace")


#    optparser.add_option ( "-v", "--var", action="extend", type="string", dest="param", metavar="PARAM", help=" could be entered as multiple -v options ")
    (options,args) = optparser.parse_args()
    if len(sys.argv) < 1 :
        mesg = len(sys.argv)
        print "incorrect number of arguments %d" % mesg
        optparser.error (mesg)
        optparser.print_help()


    if ( options.wpath == None ) :
        options.wpath = cPath+'/'

    if ( options.resultfile == None ) :
        list = sName.split('.');
        options.resultfile = options.wpath+'/'+list [0] +".log"
    else :
        options.resultfile = options.wpath+'/'+ options.resultfile


    select = options.select.lower()
    if ( not ptrTbl["action"].has_key(select) ):
        msg = " Incorrect selection " + options.select + "-- available selection is :"
        temp = ""
        for key in ptrTbl["action"] :
            msg = msg + temp + key
            temp= ", "
        print msg
        optparser.error (msg)
        optparser.print_help()


    ptrTbl["input"]=options.input
    ptrTbl["testif"]=options.testif
    ptrTbl["resultfile"]=options.resultfile
    ptrTbl["debug"]=int(options.verbose)
    ptrTbl["srcip"]=options.srcip
    ptrTbl["slaveip"]=options.slaveip
    ptrTbl["select"]=options.select.lower()
    ptrTbl["twait"]=int(options.twait)
    ptrTbl["rwait"]=int(options.rwait)
    ptrTbl["iteration"]=int(options.iteration)
    ptrTbl["logpath"]=options.wpath+"/"
    ptrTbl["password"]=options.password
    ptrTbl["user"]=options.user



    return (options)

def generate_template(ptrTbl):
    """ Description: This routine is used to generate json template used to generate zone and reverse in-addr.darpa"""

    temp = """{ "bruteforce_info": [ { "ipaddress":"10.0.100.152/24","iprange":100,"timeout":10,"protocol":"tcp","portscan":"21","packetsends":60,"user":"malwarekiller","password":"malwarekiller123","pktsize":200,"fixlen":yes,"client_int":60},
               {"ipaddress":"10.0.100.151/24","iprange":100,"timeout":10,"protocol":"tcp","portscan":"21","packetsends":60,"user":"malwarekiller","password":"malwarekiller123","pktsize":200,"fixlen":yes","client_int":60},
    	       {"ipaddress":"10.0.100.191/24","iprange":100,"timeout":10,"protocol":"tcp","portscan":"21","packetsends":60,"user":"malwarekiller","password":"malwarekiller123","pktsize":200,"fixlen":yes,"client_int":60}
    ]
}
    """
    if ( ptrTbl["debug"] ) :
        print temp
    ptrTbl["resultFD"].write(temp+"\n")
    return (PASS)



def command(ptrTbl,cmd):
    """ Description: This routine is used to send bash command through Python subprocess and return all stdouts + stderrs """
#    if ( ptrTbl["bypass"]) :  return ( PASS, "Bypass ","Bypass")
    if ( ptrTbl["debug"] > 1) :  print "CMD",cmd
    try:

        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT )
        msg = p.stdout.read()
        err = p.stderr
        #the following code line is used to wait for the process terminate so return code could be generated
        data = p.communicate()[0]
        rc= p.returncode
        if ( ptrTbl [ "debug"] > 6) : print "command RC ", rc
        return ( rc, msg,err  )
    except OSError:
        print " %s is not found " % cmd
        return ( FAIL, "cmd was not found ","cmd was not found ")



def stripHttpHeader(ptrTbl,stripurl):
    """ params ( userTbl table , url link ) ; return ( stripped url ) ---  This routine is used to strip all httP://xxxxx/ header  """
    match = re.match( r'(http:/{1,}([a-z,0-9]|\.)+/{1,})(.*)',stripurl)
    #print match
    if ( match != None ) :
        if ( ptrTbl["debug"]) :
            print "stripHttpHeader:start(%s), end(%s) " %  ( match.span(0),match.span(1))
            print  "2 Group (0) : ",match.group(0)
            print  "2 Group (1) : ", match.group(1)
            print  "2 Group (2) : ", match.group(2)
            print  "2 Group (3) : ", match.group(3)
        stripurl = match.group(3)

    else :
        if ( ptrTbl["debug"] ) :  print " stripHttpHeader: NO MATCH "
    return ( stripurl)

def parseScanJsonInput(ptrTbl):
    """ params ( userTbl table ); ret (PASS/FAIL) -- This routine is used to read in SCAN json file """
    INPUT=ptrTbl["inputFD"]
    count = 0
    new_form = 0
    data = INPUT.read()
    if ( ptrTbl["debug"])  : print "Encoded",json.dumps(data)
    mydata = json.loads(data)
    if ( ptrTbl["debug"]) : print "Decoded:",mydata
    limit=len(mydata)
    if ( ptrTbl["debug"] ) : print "LIM of scan_info  should be 1 for now ",limit
    for keys in mydata :
        print "::",keys
        if ( re.match(r"bruteforce_info",keys) != None ) :
            if (isinstance(mydata[keys],types.ListType) == True ) :
                limit = len ( mydata[keys])
                if ( ptrTbl["debug"]) :  print "++ There  are ",limit, " entries for scan_info table "
                for index in xrange ( 0,limit) :
                    ll=len(mydata[keys][index] )
                    if ( ptrTbl["debug"]) : print "  --ll",ll,type( mydata[keys][index] )
                    if (isinstance(mydata[keys][index],types.DictType) == True ) :
                        # initialize the data template for every iteration
                        info ={}
                        info["childpid"]=""
                        for kk in mydata[keys][index] :
                            datatype = type ( mydata[keys] [index] [kk] )
                            info[kk]=mydata[keys] [index] [kk]
                        if ( ptrTbl["debug"]): print "INFO",info
                        ptrTbl["bruteforce_info"].append(info)
#   if ( ptrTbl["debug"]):
    limit = len ( ptrTbl["bruteforce_info"] )
    print "2:lim",limit
    for ll in xrange (0,limit) :
        print "=>",ptrTbl["bruteforce_info"] [ll]
    return (PASS)



def increaseIp(ptrTbl,orgIp,step) :
    """ params ( ip Address, increasing step, ip mask  ); ret (PASS/FAIL) -- This routine is used to increase Ip address and skip all IPs with suffix 0 and 255 """
    match = re.search(r'/',orgIp)
    add=orgIp
    if ( match != None) :
        (add,mask)= orgIp.split('/')
        if ( ptrTbl["debug"] > 3 ) : print "increaseIp (%s) -- add  (%s)  " % ( orgIp,add)
    add = add.split('.')
    limit=len(add)
    if ( ptrTbl["debug"] > 3 ) : print "increaseIp (%s) -- step (%d) -- len(%d) " % (orgIp,step,limit)
    if ( limit != 4  ) :
        return (orgIp)
    add[3] = int(add[3])+step
    nextcount = 0
    for index in xrange ( 3,0,-1) :

        add[index] = int(add[index]) + nextcount;
        if ( add[index] > 254 ) :
            nextcount=1
            add[index] = add[index] % 255
        else :
            nextcount= 0
        if (( add[index] == 0 ) and ( index == 3 )) :
            add[index] +=1
    ipFinal = '.'.join(str(x) for x in add )
    try:
        mask
        ipFinal = ipFinal+"/"+mask
        # print "x exists"
    except UnboundLocalError:
        ipFinal
    if ( ptrTbl["debug"] > 3 ) : print "ipfinal(%s) increaseIp (%s) -- step (%d) -- len(%d) " % (ipFinal,orgIp,step,limit)
    return (ipFinal)


def checkProcId(ptrTbl,index,childPid) :
    """ params ( userTbl table, child pid ); ret (PASS/FAIL, message ) -- This routine is used to check if the children PID is legal """
    if ( (childPid[0] ==0 ) and (childPid[1] ==0 ) ) :
        if ( ptrTbl["debug"] > 6 ) :  print " checkProcId: NO CHILD TO REPORT: ", childPid
        return ( PASS, -1)
    cpid = childPid[0]
    if ( ptrTbl["debug"] > 6 ) :  print " Childid:" , childPid
    if ( ptrTbl["bruteforce_info"][index]["childpid"] == cpid ) :
            #print " checkProcId : Index(%d) Childid(%s) exits" % ( index,cpid)
        if ( ptrTbl["debug"] > 6 ) :  print " checkProcId : Index(%d) Childid(%s) exits" % ( index,cpid)
        return (PASS,index)

    if ( ptrTbl["debug"] > 3 ) :  print " checkProcId: NOT FOUND  Childid: %d "% cpid
    return (FAIL,0)

def checkClientProcId(ptrTbl,index,childPid) :
    """ params ( userTbl table, child pid ); ret (PASS/FAIL, message ) -- This routine is used to check if the children PID is legal """
    if ( (childPid[0] ==0 ) and (childPid[1] ==0 ) ) :
        if ( ptrTbl["debug"] > 6 )  :  print " checkProcId: NO CHILD TO REPORT: ", childPid
        return ( PASS, -1)
    cpid = childPid[0]
    if ( ptrTbl["debug"] > 4 ) :  print " Childid:" , childPid
    if ( ptrTbl["bruteforce_info"][index]["ClientChildpid"] == cpid ) :
            #print " checkProcId : Index(%d) Childid(%s) exits" % ( index,cpid)
        if ( ptrTbl["debug"]> 4) :  print " checkProcId : Index(%d) Childid(%s) exits" % ( index,cpid)
        return (PASS,index)
    if ( ptrTbl["debug"] > 4 ) :  print " checkProcId: NOT FOUND  Childid: %d "% cpid
    return (FAIL,0)




def killAllProcess(ptrTbl) :
    """ params ( userTbl table ); ret (PASS/FAIL,msg ) -- This routine is used to kill all child processes """
    pid = ptrTbl["parentpid"]
    os.kill(pid,signal.SIGKILL)
    msg = " Successfully kill all processes"
    #limit = len (  ptrTbl["result"] )
    #for index in xrange ( 0, limit ):
    #    if ( ptrTbl["result"][index]["status"] == RUNNING ) :
    #        pid = ptrTbl["result"][index]["childpid"]
    #        ptrTbl["result"][index]["status"] == EXIT
    #        os.kill(pid,signal.SIGKILL)
    return (PASS,msg)

def killChildProcess(ptrTbl,index) :
    """ params ( userTbl table ); ret (PASS/FAIL,msg ) -- This routine is used to kill achild process """
    childPid = ptrTbl["bruteforce_info"][index]["childpid"]
    os.kill(childPid,signal.SIGKILL)
    msg = " Successfully kill childPid="+childPid
    return (PASS,msg)

def getDate(ptrTbl) :
    """ params ( userTbl table ); ret (PASS/FAIL) -- get date """
    cmd="date +\"%Y-%m-%d at %H:%M:%S\""
    (rc,result,err) = command(ptrTbl,cmd)
    result=re.sub("\n","",result)
    return(result)



def ftp_server(ptrTbl,index,serverip,port,protocol):
    msg="dummy function"
    return(PASS,msg)

def ssh_server(ptrTbl,index,serverip,port,protocol):
    msg="dummy function"
    return(PASS,msg)
def rdp_server(ptrTbl,index,serverip,port,protocol):
    msg="dummy function"
    return(PASS,msg)



def launch_vnc(ptrTbl,vncindex,targetip,dstport):
    """ create vncserver so rdpclient could be called since rdpclient is X-client """
    timeout=20
    xwin="X"+str(vncindex)
    setup="vncserver -kill \`hostname\`:"+str(vncindex)+"; rm /tmp/.X11-unix/"+xwin+"; rm /tmp/."+xwin+"-lock; vncserver :"+str(vncindex)
    PASSWD=" -c "
    select = ptrTbl["select"]
    path = " -l " + ptrTbl["logpath"] + " -t cli_"+select+"_"+str(dstport)+".log "
    if ( re.match(NOPASSWD,ptrTbl["password"]) == None ) :
        PASSWD=" -p "+ptrTbl["password"]+" "
    #--------------
    credential=" -u "+ptrTbl["user"]+PASSWD
    cmd = "clicfg.pl "+path+" -o "+str(timeout)+ " -i 22 -n -d "+targetip+credential+" -v \" "+setup+"\"  "
    if ( ptrTbl["debug"] > 1 ) :
        print "==>launchvnc:",cmd,"\n"
    (rc,msg,error) = command(ptrTbl,cmd)
    if ( rc > 0 ) :
        returnCode = FAIL
        msg ="launch_vnc:error="+str(error)+" log=",msg
        print msg
        return(FAIL,msg)
    return(PASS,msg)

def kill_vnc(ptrTbl,vncindex,targetip,dstport):
    """ create vncserver so rdpclient could be called since rdpclient is X-client """
    timeout=20
    xwin="X"+str(vncindex)
    setup="vncserver -kill \`hostname\`:"+str(vncindex)+"; rm /tmp/.X11-unix/"+xwin+"; rm /tmp/."+xwin+"-lock;"
    PASSWD=" -c "
    select = ptrTbl["select"]
    path = " -l " + ptrTbl["logpath"] + " -t cli_"+select+"_kill_"+str(dstport)+".log "
    if ( re.match(NOPASSWD,ptrTbl["password"]) == None ) :
        PASSWD=" -p "+ptrTbl["password"]+" "
    #--------------
    credential=" -u "+ptrTbl["user"]+PASSWD
    cmd = "clicfg.pl "+path+" -o "+str(timeout)+ " -i 22 -n -d "+targetip+credential+" -v \" "+setup+"\"  "
    (rc,msg,error) = command(ptrTbl,cmd)
    if ( rc > 0 ) :
        returnCode = FAIL
        msg ="launch_vnc:error="+str(error)+" log=",msg
        print msg
        return(FAIL,msg)
    return(PASS,msg)




def http_server(ptrTbl,index,serverip,port,protocol):
    msg="dummy function"
    return(PASS,msg)

def vnc_server(ptrTbl,index,serverip,port,protocol):
    msg="dummy function"
    return(PASS,msg)


def vnc_server_old(ptrTbl,index,serverip,port,protocol):
    timeout=20
    slaveip=ptrTbl["slaveip"]
    intf=ptrTbl["testif"]
    setup="vncserver -kill \`hostname\`:1; rm /tmp/.X11-unix/X1; rm /tmp/.X1-lock; vncserver"
    PASSWD=" -c "
    select = ptrTbl["select"]
    path = " -l " + ptrTbl["logpath"] + " -t cli_"+select+"_"+str(port)+".log "
    if ( re.match(NOPASSWD,ptrTbl["password"]) == None ) :
        PASSWD=" -p "+ptrTbl["password"]+" "
    #--------------
    credential=" -u "+ptrTbl["user"]+PASSWD
    cmd = "clicfg.pl "+path+" -o "+str(timeout)+ " -i 22 -n -d "+slaveip+credential+" -v \"iptables -A INPUT  -i "+intf +"  -p all -j ACCEPT \" -v \" "+setup+"\"  "
    (rc,msg,error) = command(ptrTbl,cmd)
    if ( rc > 0 ) :
        returnCode = FAIL
        msg ="vnc_server:error="+str(error)+" log=",msg
        print msg
        return(FAIL,msg)
    return(PASS,msg)



def forkRemoteSetup(ptrTbl,index,serverip,port,protocol) :
    """ params ( userTbl table ); ret (PASS/FAIL) -- This routine is used to configure remote port in OPEN mode """
    select = ptrTbl["select"]
    size = ptrTbl["bruteforce_info"][index]["pktsize"]
    fixlen = ptrTbl["bruteforce_info"][index]["fixlen"]
    pktsend=ptrTbl["bruteforce_info"][index]["packetsends"]
    path = " -l " + ptrTbl["logpath"] + " -t cli_"+select+"_"+str(port)+".log "
    intf=ptrTbl["testif"]
        # Child process
    slaveip=ptrTbl["slaveip"]
    if ( ptrTbl["debug"] >1 ) : print "Selection=",select
    msg="index["+str(index)+"] serverip="+serverip+"port="+str(port)
    ptrTbl["resultFD"].write("forkRemoteSetup: "+msg+"\n")
    newpid = os.fork()
    if (newpid == 0) :
        if ( ptrTbl["debug"] > 0 ) : print "====> CHILD forkRemoteSetup:%s"%msg
        (rc,msg) = ptrTbl["server"][select](ptrTbl,index,serverip,port,protocol)
        if ( rc > 0 ) :
            returnCode = FAIL
            print "forkRemotesetup:error=",str(error)," log=",msg

        if ( ptrTbl["debug"] > 0 ) :
            date = getDate(ptrTbl)
            print "1#####>>>",date," CHILD  EXIT ",msg

        os._exit(0)
    else:
        # parent process
        ptrTbl["bruteforce_info"][index]["childpid"]=newpid
        ptrTbl["bruteforce_info"][index]["status"] = RUNNING
        if ( ptrTbl["debug"] > 0) :
            print "===>parent: %d, child: %d" % ( os.getpid(), newpid)
    return (PASS )


def checkPidExit ( ptrTbl,index) :
    """ params ( userTbl table , index of json table,  ); ret (PASS/FAIL,msg) -- This routine is used to verify if Child exits """
    retry = 0
    doneflag = 0
    doneflag1 = 0
    doneflag2 = 0
    msg = "NOTHING to process "
    select = ptrTbl["select"]
    while ( doneflag != 1 ) :
        try :
            childPid = os.waitpid(-1, os.WNOHANG)
        except OSError as err:
            msg="OSError: [Errno 10] No child processes"
            return(PASS,msg)
        if ( childPid < 1 ) :
            continue
        (rc1,index) = checkProcId ( ptrTbl,index,childPid)
        if ( rc1 != FAIL ) :
            doneflag1 = 1
        (rc2,index) = checkClientProcId ( ptrTbl,index,childPid)
        if ( rc2 != FAIL ) :
            doneflag2 = 1
        if ( doneflag1 == 1 and doneflag2 == 1 ) :
            doneflag = 0
        else:
            if ( doneflag1 == 1 ) :
                doneflag = 0
                continue
        if ( rc1 == FAIL  or rc1 == FAIL  ):
            retry +=1
        if ( retry > 100 ) :
            (rc,msg)=killChildProcess (ptrTbl,index);
            if ( ptrTbl["debug"]>1 ) : print msg
            doneflag = 1

    return(PASS,msg)




def sendHttpPkt(ptrTbl,index,srcip,targetip,port,srcport,xid) :
    portlist=[]
    select=ptrTbl["select"]
    msg= "sendHttpPkt: targetip(%s),srcip(%s),port(%d))" % (targetip,srcip,port)
    if ( re.match(r"postmalform",select ) is None ) :
        if ( ptrTbl["debug"] > 0)  : print msg
        rc=httptunnelget(ptrTbl,index,srcip,targetip,port,srcport,xid)
        if ( rc > 1 ) :
            msg= "Error: failed to connect to server  with ip " +targetIp+"--"+msg
            print msg
            RSLT.write(msg+"\n")
            return(FAIL,msg)
    #Get the number of packets to be sent for post
    pktsend=ptrTbl["bruteforce_info"][index]["packetsends"]

    if ( pktsend == 0 ) :
        pktsend = 1
        msg="Pktsend=1 is used by default"

    for count in xrange ( 0,pktsend) :
        select=ptrTbl["select"]
        if ( ptrTbl["debug"] > 3)  : print "sendHttpPkt: targetip(%s),srcip(%s),port(%d)): select(%s)" % (targetip,srcip,port,select)
        if ( re.match(r"httptunnel\b|postmalform\b",select ) is not None ):
            rc=httptunnelpost(ptrTbl,index,srcip,targetip,port,srcport,xid)
        else :
            rc=httptunnelget(ptrTbl,index,srcip,targetip,port,srcport,xid)
        if ( rc > 1 ) :
            msg= msg+ "-- Error: failed to connect to server  with ip " +targetIp
            print msg
            RSLT.write(msg+"\n")
            returnCode=FAIL
            #port += 1
            #srcport += 2
    return(PASS,msg)

def sendEndConnection(ptrTbl,index,srcip,targetip,port,srcport,xid) :
    """ params ( userTbl table, app index, source IP, server IP, port and client binding socket ); ret (PASS/FAIL, message ) -- This routine is end the connection with remote server """

    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)         # Create a socket object
#    clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    clientSocket.settimeout(5)
    if ( srcip is not None ) :
        try:
            clientSocket.bind((srcip,srcport))
        except socket.error as error:
            print "SRCIP",srcip," IS ALREADY BOUND"
    if ( ptrTbl["debug"] > 1 ) :  print "==>sendEndConnection: socket="+str(clientSocket)
    for  tconnect in xrange ( 0, 4) :
        try:
            clientSocket.connect((targetip,port))
            tconnect = 10
            break;
        except socket.error as error:
            msg= "sendEndConnectiont:"+targetip+" at port:"+str(port)+" is not OPENED"
            msg= msg+ "Error: sendEndconnection: socket="+str(clientSocket)
            print msg
            time.sleep(5)
            continue
    if ( tconnect < 10 ) : return (FAIL,msg)
    #-----------------------
    #terminate the connection
    #-----------------------
    msg="sendEndConnection: Finished Converstation"  + CON_END +"\n"
    clientSocket.sendto(msg,(targetip,port))
    try:
        response, serverAddress = clientSocket.recvfrom(9500)
        if ( ptrTbl["debug"] > 1 ) : print "sendCaddyPkt: ServerResponse from [ " +str(serverAddress )+ "] ="+response +"\n"
    except KeyboardInterrupt as error:
        clientSocket.close()
        return(PASS,msg)
    except socket.timeout as error:
        ptrTbl["rcvtimeout"] +=1
        print "Timeout from receiver "
    # wait for graceful terminated from server
    time.sleep(1)
    clientSocket.close()
    return(PASS,msg)


def fillHttpFieldheader(ptrTbl,dstip,headers) :
    httpfield=ptrTbl["httpfield"]
    if ( re.match ( r"refchange",httpfield) ):
        mystring= string.ascii_letters
        mydigit= string.digits
        size=10
        limit=random.randint(0,size)
        data=''.join(random.choice(mystring) for x in range (0,limit))
        name="papaya"+data
        size=20
        limit=random.randint(0,size)
        data=''.join(random.choice(mydigit) for x in range (0,limit))
        name2="green"+data
        url=name2+"."+name+".org"
        headers["Referer"]= "http://"+url+"/junk1/index1.html"
        headers["User-Agent"]="Scan_pkt_gen.py"
        return (PASS)
    if ( re.match ( r"blank",httpfield) ):
        headers["Referer"]= ""
        headers["User-Agent"]= ""
        return (PASS)
    if ( re.match ( r"omit",httpfield) ):
        return (PASS)
    #normal case
    headers["Referer"]= "http://"+dstip+"/junk1/index1.html"
    headers["User-Agent"]="Scan_pkt_gen.py"
    return (PASS)



def httptunnelget(ptrTbl,index,srcip,dstip,dstport,srcport,xid) :
    """ params ( userTbl table , index of json table ); ret (PASS/FAIL,msg) -- This routine is used to launch http tunnel get client """
    httpserver = dstip+":"+str(dstport)
    method = "GET"
    url="/reDuh.jsp?action=checkPort&port=42000"
    select=ptrTbl["select"]
    if ( re.match(r"httpgettunnel",select) is None ) :
        data="hello_world"
    else:
        fixLen = ptrTbl["bruteforce_info"][index]["fixlen"]
        size = ptrTbl["bruteforce_info"][index]["pktsize"]
        mystring = string.ascii_letters
        mydigit= string.digits
        if ( re.match(r"yes\b",fixLen) is  None ) :
            #random package
            start=size*1/3
            limit=random.randint(start,size)
        else :
            limit=size
        data=''.join(random.choice(mystring) for x in range (limit))
    url=url+"&data="+data
    if ( re.match(r"0.0.0.0",srcip) != None ) :
        http = httplib.HTTPConnection(httpserver)
    else :
        http = httplib.HTTPConnection(httpserver,source_address=(srcip,srcport))
    #print dir(http)
    params=""
    headers={}
    rc = fillHttpFieldheader(ptrTbl,dstip,headers)
#    headers["Referer"]= "http://"+dstip+"/junk1/index1.html"
#    headers["User-Agent"]="Scan_pkt_gen.py"
    if ( ptrTbl["debug"] > 2 ) :
        print  method," destip=",httpserver," Url=",url," from source ip",http.source_address," Src=",srcport," Dstport=",dstport
    # no data is needed for get
    params=""
    return(httpPktSend (ptrTbl,http,method,srcip,xid,url,params,headers) )


def httptunnelpost(ptrTbl,index,srcip,dstip,dstport,srcport,xid) :
    """ params ( userTbl table , index of json table ); ret (PASS/FAIL,msg) -- This routine is used to launch http tunnel post client """
    httpserver = dstip+":"+str(dstport)
    method = "POST"
    url="/"
    if ( re.match(r"0.0.0.0",srcip) != None ) :
        http = httplib.HTTPConnection(httpserver)
    else :
        http = httplib.HTTPConnection(httpserver,source_address=(srcip,srcport))
    #print dir(http)
    if ( ptrTbl["debug"] > 2 ) :
        print  method," destip=",httpserver,url," from source ip",http.source_address

    fixLen = ptrTbl["bruteforce_info"][index]["fixlen"]
    size = ptrTbl["bruteforce_info"][index]["pktsize"]
    mystring = string.ascii_letters
    mydigit= string.digits
    if ( re.match(r"yes\b",fixLen) is  None ) :
            #random package
        start=size*2/3
        limit=random.randint(start,size)
    else :
        limit=size
    data=''.join(random.choice(mystring) for x in range (limit))
    httpfield=ptrTbl["httpfield"]
    headers={}
    rc=fillHttpFieldheader(ptrTbl,dstip,headers)
#    headers["Referer"]= "http://"+dstip+"/junk1/index1.html"
#    headers["User-Agent"]="Scan_pkt_gen.py"
    url="/cgi-bin/query"
    params = urllib.urlencode({'xid': xid, 'data':data})
    return(httpPktSend (ptrTbl,http,method,srcip,xid,url,params,headers) )


def httpPktSend (ptrTbl,http,method,srcip,xid,url,params,headers) :
    """ parameters ( userTbl table , index of json table ); ret (PASS/FAIL,msg) -- This routine is used to send http packet & close it """

    COOKIE="xid="+str(xid)+" srcip="+srcip
    headers["Connection"]= "keep-alive"
    headers["Content-type"]="application/x-www-form-urlencoded"
    headers["Accept-Encoding"]= "zip,deflate,sdch"
    headers["Accept-Language"]="en-US,en;q=0.8"
    headers["Cookie"]=COOKIE
    headers["If-Modified-Since"]= getDate(ptrTbl)
    try:
        http.request(method,url,params,headers)
        r1=http.getresponse()
        ptrTbl["clientcount"] += 1
        ptrTbl["servercount"]  += 1
        junk = dir(r1)
        temp=r1.read()
        status=r1.status
        code =r1.reason
    except KeyboardInterrupt as error:
        http.close()
    if ( ptrTbl["debug"] > 1 ) :
        print "Code:     ",code
        print "Response: ",status
        print "content:  ",temp
    http.close()
    return(PASS)



def http_client (ptrTbl,index,srcip,dstip,dstport,srcport,vncindex) :
    return(PASS,msg)

def rdp_client (ptrTbl,index,srcip,dstip,dstport,srcport,vncindex) :
    """ This routine could not bind to any source address """
    """ sshcli.pl -d localhost -u root -p nopassword -v \" export DISPLAY=:1 ; rdesktop -u malwarekiller -p coquelico 10.11.125.74 \" -o 20"""
    USER = ptrTbl["bruteforce_info"][index]["user"]
    PWD = ptrTbl["bruteforce_info"][index]["password"]
    TMO = ptrTbl["bruteforce_info"][index]["timeout"]
    pktsend=ptrTbl["bruteforce_info"][index]["packetsends"]
    logdir=ptrTbl["logpath"]
    (rc,msg)=launch_vnc(ptrTbl,vncindex,"localhost",dstport)
    waitflag=0
    WAITLIM=10
    for count in xrange (0,pktsend) :
        waitflag +=1
        cmd="sshcli.pl -o "+ str(TMO)+ " -t "+logdir+"/bforce_rdp"+dstip+"_"+str(count)+".log"  +" -l "+ ptrTbl["logpath"] + " -d localhost -u root -p nopassword -v \" export DISPLAY=:"+str(vncindex)+"; rdesktop -u "+ USER +" -p "+PWD+" "+dstip+"\" "
        (rc,msg,err) = command(ptrTbl,cmd)
        if ( rc == FAIL ) :
            print msg+"--Error--"+str(err)

        if ( waitflag > WAITLIM ) :
            msg=" WAIT FLAG > "+str(WAITLIM)
            print msg
            waitflag=0
            (rc,msg)=launch_vnc(ptrTbl,vncindex,"localhost",dstport)

    if ( (count+1) == pktsend) :
        #clean up the vncserver to conserve resources
        (rc,msg)=kill_vnc(ptrTbl,vncindex,"localhost",dstport)
        msg="RDP Login incorrect %d times" % pktsend
        return(PASS,msg)
    msg="Successfully log through RDP count="+str(count)
    return(FAIL,msg)


def vnc_client (ptrTbl,index,srcip,dstip,dstport,srcport,vncindex) :
    """ This routine could not bind to any address """
    """vncserver -kill `hostname:1`;vncserver; vncdotool -t 5 -s 10.11.125.70::5901 -p vectra capture failed.png"""
    PWD = ptrTbl["bruteforce_info"][index]["password"]
    TMO = ptrTbl["bruteforce_info"][index]["timeout"]
    logdir=ptrTbl["logpath"]
    pktsend=ptrTbl["bruteforce_info"][index]["packetsends"]
    (rc,msg)=launch_vnc(ptrTbl,vncindex,dstip,dstport)
    waitflag=0
    WAITLIM=10
    VNC=vncindex+5900
    cmd="vncdotool -t "+ str(TMO) +" -s "+dstip+"::"+str(VNC)+ " -p "+PWD+" capture "+logdir+"/failed_vnc"+dstip +".png"
    if ( ptrTbl["debug"] > 1 ) : print cmd
    for count in xrange (0,pktsend) :
        waitflag +=1
        (rc,msg,err) = command(ptrTbl,cmd)
        if ( rc == FAIL ) :
            print msg+"--Error--"+err
        if ( waitflag > WAITLIM ) :
            msg=" WAIT FLAG > "+str(WAITLIM)
            print msg
            waitflag=0
            (rc,msg)=launch_vnc(ptrTbl,vncindex,dstip,dstport)
    if ( (count + 1 )== pktsend) :
        msg="VNC Login incorrect %d times" % pktsend
        #clean up the vncserver to conserve resources
        (rc,msg)=kill_vnc(ptrTbl,vncindex,dstip,dstport)
        return(PASS,msg)
    msg="Successfully log through VNC count="+str(count)
    return(FAIL,msg)



def ftp_client (ptrTbl,index,srcip,dstip,dstport,srcport,vncindex) :
    """ wget --bind-address=10.10.101.100 ftp://coco:vectra13579@10.11.101.100/ """
    USER = ptrTbl["bruteforce_info"][index]["user"]
    PWD = ptrTbl["bruteforce_info"][index]["password"]
    TMO=5
    pktsend=ptrTbl["bruteforce_info"][index]["packetsends"]

    if ( ptrTbl["debug"] > 2 ) : print cmd
    for count in xrange (0,pktsend) :
        cmd= "wget --bind-address="+srcip+" ftp://"+USER+":"+PWD+"@"+dstip+" -o "+ptrTbl["logpath"]+"/bforce_ftp_"+dstip+"_"+str(count)+".log -O /dev/null"
        (rc,msg,err) = command(ptrTbl,cmd)
        if ( rc == FAIL ) :
            print msg+"--Error--"+str(err)
        if ( rc == 6 ) :
            msg="Login unsuccessfully"
            if ( ptrTbl["debug"] > 2 ) : print msg+" --rc= "+str(err)
    if ( (count+1) == pktsend) :
        msg="FTP Login incorrect %d times" % pktsend
        return(PASS,msg)
    msg="Successfully log through FTP count="+str(count)
    return(FAIL,msg)


def ssh_client (ptrTbl,index,srcip,dstip,dstport,srcport,vncindex) :
    """ sshcli.pl -b 10.10.101.146 -t holla.log -l /tmp -u root -v "ls" -p nopassword -d 10.11.101.100"""
    USER = ptrTbl["bruteforce_info"][index]["user"]
    PWD = ptrTbl["bruteforce_info"][index]["password"]
    TMO=ptrTbl["bruteforce_info"][index]["timeout"]
    pktsend=ptrTbl["bruteforce_info"][index]["packetsends"]
    logdir=ptrTbl["logpath"]
    for count in xrange (0,pktsend) :
        cmd="sshcli.pl -b "+srcip+" -t "+logdir+"/bforce_ssh_"+dstip+"_"+str(count)+".log"  +" -l "+ ptrTbl["logpath"] + " -u "+USER+" -p "+PWD+" -v \"ls\" -d "+dstip
        (rc,msg,err) = command(ptrTbl,cmd)
        if ( rc == FAIL ) :
            print msg+"--Error--"+str(err)
    if ( (count+1) == pktsend) :
        msg="SSH Login incorrect %d times" % pktsend
        return(PASS,msg)
    msg="Successfully log through SSH count="+str(count)
    return(FAIL,msg)



def forkSendingLoginPkt(ptrTbl,index,targetip,srcip,destport,srcport,vncindex) :
    """ params ( userTbl table ); ret (PASS/FAIL) -- This routine is used to configure fork a process to send http packets to remote server """
    select = ptrTbl["select"]
    size = ptrTbl["bruteforce_info"][index]["pktsize"]
    pktsend=ptrTbl["bruteforce_info"][index]["packetsends"]
    path = " -l " + ptrTbl["logpath"] + " -t cli_"+select+"_"+str(destport)+".log "
    intf=ptrTbl["testif"]
        # Child process
    slaveip=ptrTbl["slaveip"]
    if ( ptrTbl["debug"] >1 ) : print "Selection=",select
    newpid = os.fork()
    if (newpid == 0) :
        msg="["+str(index)+" Targetip="+targetip+" Srcip="+srcip+" DestPort="+str(destport)+" Srcport="+str(srcport)+ " VNCindex="+str(vncindex)
        if ( ptrTbl["debug"] > 0 ) : print "====> CHILD forkSendingHttpPkt:%s"%msg
        (rc,msg) = ptrTbl["loginprotocol"][select] (ptrTbl,index,srcip,targetip,destport,srcport,vncindex)
        #(rc,msg) = sendHttpPkt(ptrTbl,index,srcip,targetip,destport,srcport,xid)
        if ( rc > 0 ) :
            returnCode = FAIL
            print "forkSendingLoginPkt:Error ",msg
        if ( ptrTbl["debug"] > 0 ) :
            date = getDate(ptrTbl)
            print "1#####>>>",date," CHILD  EXIT ",msg
#        (rc,msg)=sendEndConnection(ptrTbl,index,srcip,targetip,destport,srcport)
        os._exit(0)
    else:
        # parent process
        ptrTbl["bruteforce_info"][index]["ClientChildpid"]=newpid
        ptrTbl["bruteforce_info"][index]["ClientStatus"] = RUNNING
        if ( ptrTbl["debug"] > 0 ) :
            print "===>parent: %d, child: %d" % ( os.getpid(), newpid)
    return (PASS)

def generateGenericPkt(ptrTbl,scan_index):
    """ params ( userTbl table , index of json table, type of action (DROP OPEN, REJECT ) ); ret (PASS/FAIL,msg) -- This routine is used to generate scanning packet and remotely configure the Slave Host with the right IPTABLES configuration """
    srcrange = int (ptrTbl["srcrange"])
    protocol = ptrTbl["bruteforce_info"][scan_index]["protocol"]
    dstcount = 1
    RSLT = ptrTbl["resultFD"]
    returnCode=PASS
    rc=0
    #------------------------------------
    # Get src ip and get rid off the mask
    #------------------------------------
    srcip= ptrTbl["srcip"]
    tt=srcip.split("/")
    srcip=tt[0]
    orgSrcip=tt[0]
    #-----------------------
    # Set up destination
    #-----------------------
    dstIprange=int ( ptrTbl["bruteforce_info"][scan_index]["iprange"])
    targetip = ptrTbl["bruteforce_info"][scan_index]["ipaddress"]
    tt=targetip.split("/")
    targetip=tt[0]
    orgTargetip=tt[0]
    select=ptrTbl["select"]

    #-----------------------
    # Set up port
    #-----------------------
    portlist = ptrTbl ["bruteforce_info"] [scan_index]["portscan"].split(',')
    limit = len(portlist)
    portentry =0
    port = int ( portlist[portentry])
    if ( ptrTbl["bypass"] != True ):
    #----------------------------
    # Set up remote server
    #----------------------------
        if ( ptrTbl["debug"] > 1 )  : print "=====> Remote Set up : targetip(%s),port(%d))" % (targetip,port)
        msg="RemoteSetup: Range="+str(srcrange)+"target ip="+targetip+"srcip="+srcip+" port="+str(port)
        print msg
        ptrTbl["resultFD"].write(msg+"\n")
        rc = forkRemoteSetup(ptrTbl,scan_index,targetip,port,protocol)
        if ( rc > 1 ) :
            returnCode=FAIL
            slaveip = ptrTbl["slaveip"]
            msg= "Error: failed to connect to slave host with ip " +slaveip+"--"+msg
            print msg
            RSLT.write(msg+"\n")
#    if ( re.search(r"vnc\b|rdp\b",select) ):
#        wait = 15
#        print "Wait for ",wait," seconds"
#        time.sleep(wait)

    #------------------------------------
    # Get src ip and get rid off the mask
    #------------------------------------
    srcip= orgSrcip
    #-----------------------
    # Set up destination
    #-----------------------
    targetip=orgTargetip
    select=ptrTbl["select"]
    if ( ptrTbl["debug"] > 1)  : print "generateDnsPkt: targetip(%s),srcip(%s),range(%d))" % (targetip,srcip,srcrange)
    #-----------------------
    # Set up port
    #-----------------------
    portlist = ptrTbl ["bruteforce_info"] [scan_index]["portscan"].split(',')
    limit = len(portlist)
    portentry =0
    port = int ( portlist[portentry])
    iprange=ptrTbl ["bruteforce_info"] [scan_index]["iprange"]
    vncindex=0
    for srccount in xrange ( 0,srcrange) :
        targetip=orgTargetip
        for dstcount in xrange ( 0,iprange) :
            vncindex +=1
            srcport=0
            if ( ptrTbl["debug"] > 1)  : print "=====> GENERATEDNSPKT(%d): targetip(%s),srcip(%s),port(%d),vncindex(%d))" % (srccount,targetip,srcip,port,vncindex)
            rc=forkSendingLoginPkt(ptrTbl,scan_index,targetip,srcip,port,srcport,vncindex)
            if ( rc > 1 ) :
                returnCode=FAIL
                slaveip = ptrTbl["slaveip"]
                msg= "Error: failed to connect to slave host with ip " +slaveip+"--"+msg
                print msg
                RSLT.write(msg+"\n")
        #---------------------
        #  Increase Destination IP
        #---------------------
            targetip = increaseIp(ptrTbl,targetip,1)
        #---------------------
        #  Increase Source IP
        #---------------------
        srcip = increaseIp(ptrTbl,srcip,1)
    #---------------------
    #  Verify if childid exits
    #---------------------
    (rc,msg)=checkPidExit(ptrTbl,scan_index)
    if ( rc >1 ) : returnCode = FAIL
    return (PASS)

def genericpkt(ptrTbl) :
    """ params ( userTbl table ); ret (PASS/FAIL,msg) -- This routine is used to generate DNS tunnel  traffic based on  control input file"""
    msg = " "
    lim = len(ptrTbl ["bruteforce_info"])
    globalrc = PASS
    select=ptrTbl["select"]
    for index in xrange(0,lim) :
        date = getDate(ptrTbl)
        entry=ptrTbl ["bruteforce_info"][index]
        print "Login Selection ",date," --",select.upper()
        portlist = entry["portscan"].split(',')
        limit = len(portlist)
        protocol=entry["protocol"]
        if ( re.match(r"udp",protocol) ) :
            globalrc=FAIL
            msg += "line (" +str(index)+") of json file contains udp which is not supported for httptunnel \n"
            continue
        rc=generateGenericPkt(ptrTbl,index)
        if ( rc == PASS) :
            msg += "line (" +str(index) +") of json file was successfully executed \n"
        else :
            globalrc=FAIL
            msg += "Execution of line (" +str(index) +") of json file was failed  \n"
    return(globalrc,msg)


def generic(ptrTbl ) :
    msg = " dnstunnel is selected with iteration" + str(ptrTbl["iteration"])
    print msg
    ptrTbl["resultFD"].write(msg+"\n")
    count = 0
    if ( ptrTbl["iteration"] == 0 ) :
        while (1) :
            print "==>iteration %d" % count
            (rc,msg)= genericpkt(ptrTbl)
            if ( rc == FAIL ) :
                return(FAIL,msg)
            count +=1
    else :
        for count in xrange ( 0,ptrTbl["iteration"] ) :
            print "==>iteration %d" % count
            (rc,msg)= genericpkt(ptrTbl)
            if ( rc == FAIL ) :
                return(FAIL,msg)
    return(rc,msg)



#--------
def printInputLog (ptrTbl) :
    inputTbl=[]
    date = getDate(ptrTbl)
    msg="###############"
    inputTbl.append(msg)
    msg="Start Time"+date
    msg="Using Scan json configuration  file: " + ptrTbl["input"]
    inputTbl.append(msg)
    msg="Result will be saved in outputfile: " +  ptrTbl["resultfile"]
    inputTbl.append(msg)
    msg= "User is set to: " +  str(( ptrTbl["user"] ))
    inputTbl.append(msg)
    msg= "Password is set to: " +  str(( ptrTbl["password"] ))
    inputTbl.append(msg)
    msg="Source Host IP: " +  ptrTbl["srcip"]
    inputTbl.append(msg)
    msg="Source range : " +  str(ptrTbl["srcrange"]  )
    inputTbl.append(msg)
    msg="Slave Host IP: " +  ptrTbl["slaveip"]
    inputTbl.append(msg)
    msg="Iteration:  " +  str(ptrTbl["iteration"]  )
    inputTbl.append(msg)
    msg="Random wait : " +  str(ptrTbl["rwait"]  )
    inputTbl.append(msg)
    msg="Test Interface :" +  ptrTbl["testif"]
    inputTbl.append(msg)
    msg="Static wait :  " +  str(ptrTbl["twait"] )
    inputTbl.append(msg)
    msg="Debug level  is set : " +  str(ptrTbl["debug"] )
    inputTbl.append(msg)
    msg="Test selection :  " +  ptrTbl["select"]
    inputTbl.append(msg)
    msg= "Directory where logs will be saved to: " +  ( ptrTbl["logpath"] )
    inputTbl.append(msg)
    msg= "Bypass traffic generator is set to: " +  str( ptrTbl["bypass"] )
    inputTbl.append(msg)
    msg="###############"
    inputTbl.append(msg)
    lim = len(inputTbl)
    for line in inputTbl :
        print line
        ptrTbl["resultFD"].write(line+"\n")


    return ( PASS)

#-------------
# Default Value
#---------------
userTbl= { "input":None, "resultfile":None, "output": None ,
           "rwait":0,"twait":0,
           "debug":None, "result":[ ],"bypass":False,
           "logpath":None, "inputFD":None, "resultFD":None,"clientcount":0,"servercount":0,
           "concurrent":None,"template":SCNAME,"parentpid":None,
           "bruteforce_info":[],"srcrange":0,"dstrange":0,
           "dnsip":0,"srcip":0,"iteration":1,"slaveip":None,
           "rcvtimeout":0,"testif":"eth1",
           "action":{ "ftp":generic,"ssh":generic,"rdp":generic,"http":generic,"vnc":generic },
           "loginprotocol":{ "ftp":ftp_client,"ssh":ssh_client,"rdp":rdp_client,"http":http_client,"vnc":vnc_client },
           "server":{ "ftp":ftp_server,"ssh":ssh_server,"rdp":rdp_server,"http":http_server,"vnc":vnc_server},

}



#-----------------
# Main
#-----------------
# if main function is defined then call it
if __name__ == "__main__" :
    myinput=main(userTbl,curr_path,scriptname)

#    userTbl["client"]=myinput.client
    userTbl["srcrange"]=int(myinput.srcrange)
    if ( userTbl["srcrange"] < 1 ) :
        userTbl["srcrange"]=1
    userTbl["bypass"]=myinput.bypass
    if ( userTbl["srcip"] == None  ) :
        userTbl["srcrange"] = 1
        userTbl["srcip"] = "0.0.0.0"

else :
    print " Error : Missing MAIN Subroutine to handle user inputs "
    exit (1)
#-----------------

if ( myinput.tempgen ) :
    tempname = userTbl["logpath"] + "/"+ userTbl["template"]
    try:
        userTbl["resultFD"] = open ( tempname , "w" )
    except IOError as err:
        print "Error: Could not write to File \'%s\'  -- %s %s " % (tempname,err.errno, err.strerror)
        exit (1)
    print "%s" % generate_template.__doc__
    generate_template(userTbl)
    print "Template file (%s ) is generated \n" % tempname
    exit (0)



# Get the current Process ID
userTbl["parentpid"]=os.getpid()

#print " PARAMS ", myinput.param


resultfile= userTbl["resultfile"]
try:
    resultFN = open ( resultfile , "w" )
except IOError as err:
    print "Error: Could not write to File \'%s\'  -- %s %s " % (resultfile,err.errno, err.strerror)
    exit (1)
userTbl["resultFD"]=resultFN

#print input log
rc=printInputLog(userTbl)


if ( os.path.exists(userTbl["logpath"] ) == False ) :
        cmd = " mkdir -p  " + userTbl["logpath"]
        rc = os.system(cmd)

if ( userTbl["input"] != None ) :

    if (  os.path.isfile( userTbl["input"]) == False ) :
        print "Error: DNS json configuration input file \'%s\' is not found " % userTbl["input"]
        exit (0)

    try:
        inputFN = open ( userTbl["input"] , "r" )
    except IOError as err:
        print "Error: Could not read File \'%s\'  -- %s %s " % (userTbl["input"],err.errno, err.strerror)
        exit (1)
    userTbl["inputFD"]=inputFN

#Parse Scan json file
rc = parseScanJsonInput(userTbl)

select=userTbl["select"]
(rc,msg) = userTbl["action"][select] (userTbl)
date = getDate(userTbl)
msg="Ending time:"+date+"\n"
msg= msg+"Client Sending Packets: "+ str(userTbl["clientcount"]) + "\nServer Sending Packets: "+ str(userTbl["servercount"])

print msg
resultFN.write(msg+"\n")
#--- Program End ---------
inputFN.close()
resultFN.close()
exit (0)
