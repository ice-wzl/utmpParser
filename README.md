# utmpParser
Small script to parse u|w|btmp identifying counts of logins from specific ips, logon times from a specific host, and outside working hour login detection
Script does not require libraries outside of the Python stdapi

## Help Menu 
````
python3 utmp_parser.py --help
usage: utmp_parser.py [-h] -f FILE [-c] [-i IP] [-w WORKING]

utmp parser

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  specified input b|w|utmp file to parse
  -c, --count           prints the ips and the amount of logins
  -i IP, --ip IP        print timestamps of logins from specific ip
  -w WORKING, --workinghours WORKING
                        normal working hours, returns login results outside of your range, format -w 0900-1700
````
- pass in the file to examine with `-f`
- use `-c` to get a first overview of the hosts that frequently login
````
python3 utmp_parser.py -f /var/log/wtmp -c  
192.168.15.172  : 62
tmux            : 49
70.169.145.92   : 16
192.168.1.34    : 12
192.168.15.128  : 9
192.168.1.172   : 7
192.168.15.34   : 7
tty2            : 6
150.136.180.81  : 6
100.93.30.118   : 4
--snip--
````
- drill down further examining a suspicious ip address
````
python3 utmp_parser.py -f /var/log/wtmp -i 150.136.180.81
2023/11/29 09:42:03 : USER
2023/11/29 09:39:47 : USER
2023/11/29 09:30:59 : USER
2023/11/29 08:26:02 : USER
2023/11/29 08:25:25 : USER
2023/11/27 10:24:19 : USER
````
- if you have set working hours or times the system is used, scan the entire file for logins that occur outside of the working hours
````
python3 utmp_parser.py -f /var/log/wtmp -w 0800-1700
['USER', 2125568, 'pts/3', 'ts/3', 'ubuntu', '192.168.1.172', 0, 0, 0, '2023/12/17 21:38:27', 525452, IPv4Address('192.168.1.172')]
['USER', 2169983, 'pts/0', 'ts/0', 'ubuntu', '71.125.89.170', 0, 0, 0, '2023/12/23 19:30:10', 605789, IPv4Address('71.125.89.170')]
['USER', 2191334, 'pts/0', 'ts/0', 'ubuntu', '71.125.89.170', 0, 0, 0, '2023/12/23 20:21:28', 821490, IPv4Address('71.125.89.170')]
['USER', 2292536, 'pts/0', 'ts/0', 'ubuntu', '100.93.30.118', 0, 0, 0, '2024/01/06 19:42:57', 167794, IPv4Address('100.93.30.118')]
````
- this dumps the entire struct entry without further parsing
- All of these commands work on the btmp and utmp files as well!
- If you have some ideas to expand the script throw in a PR or open and issue with your idea.
