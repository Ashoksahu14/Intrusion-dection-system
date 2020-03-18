****************Installation and execution instructions

Copy IDS.tar.gz to whatever directory you want to install the software.

As a root user run following

tar -xzvf IDS.tar.gz

command to install the software: ./installAnalyzer <path to pip>

For example: ./installAnalyzer /usr/bin/pip3

cd networkAnalyzer directory and run following command to run the software.

python3 NetworkAnalyzer.py

************About the software*******************
The software consists of 2 modes:
1. Learning mode
2. Monitoring mode

Learning mode is optional. Purpose of this mode to to learn reference values for flow per second(FPS) for different countries.
This mode currently runs for 60 seconds. 

Monitoring mode: This is the main mode. Here traffice flow is monitored as requested.

Anomalies are monitored and reported per country. 

A feature I have added which was not requested is, disabling reporting/alarming for a country for 10 mins if an anomaly was 
already reported. This is to avoid too many reporting.

Some of the configuration defined as global variables. These can be made configurable parameter. 

Main thread starts the learning thread and a timer which when fired ends the learning mode. At this point, a flow_procesor thread and a timer
thread (called monitor) is started. Flow processor processes the pkt flows and updates stats. Timer runs every second and does the monitoring of stats
and raises alarm if conditions if deemed necessary.

Main thread gets data from the http stream and puts in a data queue which is processed by flow processor thread.

Lock has been used to lock access to shared dictionary of stats.

The software also has logging feature which is logging various data points for review in a file call analyzer.log in the present directory.

**********Enhancements***********
1. When traffic is flagged as suspicious flowing actions can be taken, these can also be made configurable.
   a. Blocking the source ip at the firewall level.
   b. sending snmp trap alarm
   c. adding the ip in black list
   d. emailing the concerned people.
  
