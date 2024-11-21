@echo off
cd /d C:\workspace\ffmpeg
ffmpeg -re -i http://devimages.apple.com/iphone/samples/bipbop/bipbopall.m3u8 -c copy  -f mpegts  tcp://127.0.0.1:9103