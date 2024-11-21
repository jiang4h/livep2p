livep2p jiang4h@hotmail.com

base:
	app_log.c app_log.h : logging module
	btype.h : portable definitions
	cJSON.c cJSON.h : third-party json library
	memstat.c : memory dialogistic module
	uthash.h : third-party hash library
	
rudp: reliable udp module based on ikcp and libevent
    ikcp.c ikcp.h : third-party reliable udp library - modified
	
tsdemux : ts parser module

p2papp.c p2papp.h : main entry
p2pblock.c p2pblock.h : data block which contains packs
p2pcache.c p2pcache.h : data cache which contains blocks
p2pm3u8.c p2pm3u8.h : m3u8 generator
p2phttpsrv.c p2phttpsrv.h : http server for video players
p2pmgmt.c p2pmgmt.h : manage channels
p2pmsg.c p2pmsg.h : message parser
p2ppeer.c p2ppeer.h : peer info
p2psched.c p2psched.h : core module for a channel
p2ptcpsrv.c p2ptcpsrv.h : tcp server to receive ts source
p2ptrksrv.c p2ptrksrv.h : tracker server

build for linux: install libevent and zlib ahead
cd build
make linux

build for android:
cd build
make android_arm

tracker web: http://<trksrv ip>:<port>
	api: http://<trksrv ip>:<port>/json/peerinfo
	     http://<trksrv ip>:<port>/json/authcode?cid=1
	     
play: http://<httpsrv ip>:<port>/live?cid=1&auth=<authcode>
	  http://<httpsrv ip>:<port>/m3u8?cid=1&auth=<authcode>