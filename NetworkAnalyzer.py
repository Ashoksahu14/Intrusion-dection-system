import json
import requests
import threading
from queue import Queue
import time
import geoip2.database
import re
from collections import OrderedDict
import logging
import math

###########################configuration########################################

# if the traffic is more or less by this % from normal 
# for 30 seconds or more raise alarm (flag)
abnormality_percentage = 100

#Collect stats in a bucket (data_flow_per_sec_by_country dictionary) 
#for this many seconds.
compare_stats_timer_conf = 1

#Once traffic of alarming amount has been detected, we monitor flow
#for this many seconds and if the condition stays true for this time we 
#raise alarm.
monitor_alarm_timer_conf = 30

#Once an event is disabled, moitoring will be off for this
#configuration to avoid generating too many alerts
turn_monitoring_on_timer_conf = 600

#program will learn and establish baseline values for this many seconds by 
#taking an average of traffic flow during this time. Baseline is established
#for each country and is later used in other calculations. 
learn_baseline_timer_conf = 60

###########################configuration########################################


###########################Globals##############################################

#lock to syncronize access to the dictionary of stats
data_flow_dict_lock = threading.Lock()

#size of queue of input stream
#q_size = int(50000)
q_size = 50000

#network data queue, main thread adds to the queue and flow_processor 
#processes the queue.
data= Queue(q_size)


#dictionary of country.iso_code and a list of stats

#dictionary key is the country.iso_code 
#list values are as described below:
#if {'CN',[x,y,a=False,b=False]} where 'CN' is the iso_code
#x is number of pkts aggregated in current second so far.
#a is True if this flow is already suspicious i.e. currently being monitored for 
# abnormal traffic (watching for 30 seconds) to raise alarm.
# if a is True then y represents how many seconds this flow has
# has had abnormal flow.
# b is set to True if alarm for this flow was just raised
# and we don't want to raise another alarm for n mins where n is configured.
# This is to avoid too many notification to administrators
# if b is False then only we are processing this flow.
#Alarm is raised if y reaches a count of 30 (can be made configurable)
#After alarm is raise y and a are reset to original value and x is reset to '0'
#after each second.
data_flow_per_sec_by_country = OrderedDict()

#the algorithm runs first n number of seconds and learns refrence
#ranges per country and stores in this dictionary. This dictionary can also be
#provided by administrator from begining and then we can skip the learning step.
data_flow_per_sec_by_country_reference = OrderedDict()

#ip address pattern, used to look for source ip address in the input string
ip_addr_pattern= re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    
#Pattern to extract number of flow(pkts) in the current stream
num_flow_pattern = re.compile(r'flows\": .')
    
#Reader for our database file
database_reader = geoip2.database.Reader('./GeoLite2-Country.mmdb') 

logging.basicConfig(filename='analyzer.log',filemode='w',\
        format='%(asctime)s - %(message)s')

#Flag to indicate if program is in learning mode.
#if this is true, we are first trying to learn reference values.
#only enabled once in begining.
learning = True
###########################Globals##############################################
    
def end_learning():
    global learning 
    learning = False
    logging.warning("Ending learning activity")
 
def start_monitoring(k0,k1):
    global data_flow_per_sec_by_country
    global data_flow_per_sec_by_country_reference
    with data_flow_dict_lock:
       k=k0+k1
       data_flow_per_sec_by_country[k][3]= False
       logging.warning(f'after turning on monitoring for {k} \
               {data_flow_per_sec_by_country[k]}')

#Runs every second.
#Goal is pkts/flows per second per country and also monitor for abnormal traffic\
#        and take action as needed
def process_new_stats():
    ''' processes stats in data_flow_per_sec_by_country 
    compares it to reference values in data_flow_per_sec_by_country_reference
    to find out percentage increase in traffic from reference range. If 
    percentage is more than configured value which is currently set to 100, it
    monitors the flow for next 30 seconds(also can be configured). If traffic
    is deemed abnormal for 30 seconds msg is printed to the console. Alarms, 
    snmp traps, email msgs and other actions like blocking the source ip address
    traffic can be done at this point (future enhancements). At this point we 
    also set monitoring/alarming off for this stream for next 10 mins(also can 
    be configured). This is done to avoid to many 
    messages/alarms to the administrators/operators.
    
    If at any point before 30 second the traffic becomes normal, we reset the 
    monitoring flag back to False i.e. we consider the flow non suspicious.
    
    After every seconds num pkts is reset to '0' '''
    global data_flow_per_sec_by_country
    global data_flow_per_sec_by_country_reference
    try:
        precentage_traffic_increase = 0
        logging.debug(f'Inside process_new_stats')
        with data_flow_dict_lock:
            for key in data_flow_per_sec_by_country:              
                if key not in data_flow_per_sec_by_country_reference:
                    logging.warning("adding key " + key + "to data_flow_per_sec_by_country_reference")    
                    data_flow_per_sec_by_country_reference[key]=1

                if data_flow_per_sec_by_country[key][3] == False:
                   if data_flow_per_sec_by_country[key][0]>0:
                      precentage_traffic_increase = \
                              int(((data_flow_per_sec_by_country[key][0]-\
                              data_flow_per_sec_by_country_reference[key]) \
                              / data_flow_per_sec_by_country_reference[key])*100)   
                      logging.debug(f'process_new_stats: key: {key} \
                              precentage_traffic_increase: {precentage_traffic_increase} \
                              data_flow_per_sec_by_country: \
                              {data_flow_per_sec_by_country[key]}\
                              data_flow_per_sec_by_country_reference: \
                              {data_flow_per_sec_by_country_reference[key]}')                                      
                   else:
                      precentage_traffic_increase = 0                   
                                 
                   if abs(precentage_traffic_increase)>=abnormality_percentage:
                       logging.warning(f'Abnormal traffic noted: key: {key} \
                               precentage_traffic_increase: {precentage_traffic_increase} \
                               data_flow_per_sec_by_country: {data_flow_per_sec_by_country[key]}\
                               data_flow_per_sec_by_country_reference: \
                               {data_flow_per_sec_by_country_reference[key]}')  
                       data_flow_per_sec_by_country[key][1] +=1
                       if data_flow_per_sec_by_country[key][1]>=monitor_alarm_timer_conf:
                          #raise alarm and disable monitoring for this flow for configured 
                          #amount of time
                          logging.warning(f'Alarm condition True, Raised alarm \
                                  for key {key}')
                          print(f'Alarm condition True, Raised alarm for iso_code {key}')
                          data_flow_per_sec_by_country[key][3]= True
                          #reset remaining values for other indices
                          data_flow_per_sec_by_country[key][2]= False
                          data_flow_per_sec_by_country[key][1]= 0                          
                          logging.warning(f'calling start_monitoring key: {key}')
                          #start a timer to set data_flow_per_sec_by_country[key][3] 
                          #to False after after configured amount of time.
                          threading.Timer(turn_monitoring_on_timer_conf,\
                                  start_monitoring,key).start()
                          
                       else:                      
                          data_flow_per_sec_by_country[key][2]= True
                   else:
                      if data_flow_per_sec_by_country[key][2]== True:
                         logging.warning(f'process_new_stats: Clearing Abnormal\
                                 Traffic flag for key {key}')
                         
                      data_flow_per_sec_by_country[key][2]= False
                      data_flow_per_sec_by_country[key][1]= 0
                #reset stats
                data_flow_per_sec_by_country[key][0]=0
        
        #restart 1 sec timer to collect stats per second
        threading.Timer(compare_stats_timer_conf,process_new_stats).start()
   
    except Exception as e:
        logging.warning(f'Exception while process_new_stats: {e}')
        threading.Timer(compare_stats_timer_conf,process_new_stats).start()

             
def find_country_iso_code_and_num_flows(input_stream):
    try:
        #extract number of flow(pkts)
        num_flows_str = num_flow_pattern.search(input_stream)
        num_flows_match = num_flows_str.group()
        num_flows = int(num_flows_match[-1])
                  
        #extract source ip address              
        src_ip = ip_addr_pattern.search(input_stream)                       
        #pull country corresponding to the source ip address
        dbinfo = database_reader.country(src_ip.group())
        return dbinfo.country.iso_code,num_flows
    except Exception as e:
        logging.debug(f'iso_code not found for {input_stream} src_ip \
                        {src_ip.group()} exception {e}')
        return None,0
    
    
def learn_reference_values():     
    i=0
    global data_flow_per_sec_by_country
    global data_flow_per_sec_by_country_reference
    while learning == True:   
       if data.empty()==False:
          try:       
              i+=1          
              iso_code,num_flows = find_country_iso_code_and_num_flows(data.get())
              data.task_done()
              if iso_code !=None:
                  with data_flow_dict_lock:
                      if iso_code in data_flow_per_sec_by_country_reference:
                        data_flow_per_sec_by_country[iso_code][0]+= num_flows
                        data_flow_per_sec_by_country_reference[iso_code]+= num_flows
                      else:
                        data_flow_per_sec_by_country[iso_code]= [num_flows,0,False,False]
                        data_flow_per_sec_by_country_reference[iso_code]= num_flows
                  if i%50000 == 0:          
                     logging.warning("learned_reference_value_dictionary created: "\
                             + str(data_flow_per_sec_by_country_reference))                     
                     i=0
          except Exception as e:
                logging.warning( f'learn_reference_values: exception occoured \
                        iso_code {iso_code} num_flows: {num_flows} remaining \
                        queue size {data.qsize()} exception {e}')
       else:
          logging.warning("input data stream empty")
          time.sleep(1)
    
    for key in data_flow_per_sec_by_country_reference:        
        reference = int(math.ceil(data_flow_per_sec_by_country_reference[key]/ \
                learn_baseline_timer_conf))
        data_flow_per_sec_by_country_reference[key] = reference 
        
    logging.warning(f'learn_reference_values Reference Dictionary created: \
            {data_flow_per_sec_by_country_reference}')
    logging.warning(f'learn_reference_values Other Dictionary created: \
            {data_flow_per_sec_by_country}')
    flow_processor.start() 
    monitor.start()
    

def process_queue():
    '''#1.Get data from queue
    #2.Search source ip address
    #3.Find corresponding country for the source ip address.
    #4.Find number of flows in the pkts and iso_code for the flow
    #5.Get lock for the dictionary of stats
    #6.Update stats
    #7.Release lock'''
    global data_flow_per_sec_by_country
    global data_flow_per_sec_by_country_reference
    i=0
    while True:   
       if data.empty()==False:
          try:          
              i+=1
              input_stream = data.get()
              iso_code,num_flows = find_country_iso_code_and_num_flows(input_stream)
              data.task_done()
              if iso_code !=None:
                  with data_flow_dict_lock:
                      if iso_code in data_flow_per_sec_by_country:
                         data_flow_per_sec_by_country[iso_code][0]+= num_flows
                      else:
                        data_flow_per_sec_by_country[iso_code]= [num_flows,0,False,False]
                        data_flow_per_sec_by_country_reference[iso_code]=num_flows              
              
              if i%100000 == 0:          
                 k=0
                 for keys in data_flow_per_sec_by_country:
                     k+=1
                 logging.debug(f'process_queue Dictionary created: \
                         {data_flow_per_sec_by_country} Num keys: {k}')

                 k=0
                 for keys in data_flow_per_sec_by_country_reference:
                     k+=1
                 logging.debug(f'process_queue Reference Dictionary created: \
                         {data_flow_per_sec_by_country_reference} Num keys: {k}')                 
                 i=0
          except KeyError as a:
              logging.warning(f'process_queue: exception occoured {iso_code} \
                      num_flows: {num_flows} remaining queue size {data.qsize()}\
                      exception Key error: {a}')        
              continue
          except Exception as e:
              logging.warning(f'process_queue: exception occoured {iso_code} \
                      num_flows: {num_flows} remaining queue size {data.qsize()}\
                      exception: {e}')
              logging.warning(f'process_queue input stream: {input_stream}')
              logging.warning(f'process_queue Reference Dictionary created: \
                      {data_flow_per_sec_by_country_reference}')
              continue
       else:
          logging.debug(f'No data to analyze qsize: {data.qsize()}')
          continue


baseline_learner_thread = threading.Thread(target=learn_reference_values)

monitor = threading.Timer(compare_stats_timer_conf,process_new_stats)

end_learning_activity_timer = threading.Timer(learn_baseline_timer_conf,end_learning)

flow_processor = threading.Thread(target=process_queue)

#set daemon to true to make sure child dies if parent terminates
flow_processor.daemon = True
monitor.daemon= True
end_learning_activity_timer.daemon = True
baseline_learner_thread.daemon = True
 
#Create a learner thread and a timer thread to stop learning in configured time
#Start the threads
#Run for ever to get input from http stream
if __name__ == '__main__':
    baseline_learner_thread.start()
    end_learning_activity_timer.start()
    print("Starting network monitoring app...")  
    #request pointing to the http stream
    
    while True:
       try:
           r = requests.get('http://18.236.247.80:8080/fps/', stream=True)

           if r.encoding is None:
              r.encoding = 'utf-8'

           i=0
           for line in r.iter_lines(decode_unicode=True):
              if line:
                i+=1
                if i%5000 == 0:
                   logging.warning(f'input stream queue size {data.qsize()}')
                   i=0
                data.put(line)    
       except Exception as e:
          logging.warning(f'Response status code {r.status_code}, \
                  Exception in main loop: {e}' )
          continue
          
