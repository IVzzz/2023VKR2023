#!/usr/bin/env python
# coding: utf-8

# In[46]:


import re
import datetime

example = """13:03:41.795599 IP udp032919uds.hawaiiantel.net.6881 > 192.168.1.2.52055:
Flags [.], seq 640160396:640161844, ack 436677393, win 2050, options [nop,nop,TS val 3805626438 ecr 4677385],
length 1448"""


# In[71]:


def connection_parser(ex):
    conn = ex+'END'
    pack_size = 65535
    result = {'Src IP':'', 'Src Port':'','Dst IP':'','Dst Port':'','Protocol':'',
              'Timestamp':'','Flow Duration':'','Flow Byts/s':'','Flow Pkts/s':'','Pkt Len Var':'','Down/Up Ratio':''}
    
    substr = re.search('IP (.+?) >', conn)
    if substr:
        result['Src IP'] = substr.group(1)[:-5]
        result['Src Port'] = substr.group(1)[-4:]
    
    substr = re.search('> (.+?):', conn)
    if substr:
        result['Dst IP'] = substr.group(1)[:-4]
        result['Dst Port'] = substr.group(1)[-4:]
    
    result['Protocol'] = 'TCP'
    
    now = str(datetime.datetime.now()).split(' ')
    now = now[0].split('-')
    conn_time = conn[:8].split(':')
    result['Timestamp'] = '{0}/{1}/{2} {3}:{4}:{5}'.format(now[1],now[2],now[0],conn_time[0],conn_time[1],conn_time[2])
    
    substr = re.search('length (.+?)END', conn)
    if substr:
        result['Pkt Len Var'] = int(substr.group(1))
        
    substr = re.search('.(.+?) IP', conn)
    if substr:
        result['Flow Duration'] = int(substr.group(1).split('.')[1])
        
    result['Down/Up Ratio'] = 1.0
    step = 10**(len(str(result['Flow Duration'])))
    result['Flow Pkts/s'] = step * result['Pkt Len Var'] / result['Flow Duration']
    result['Flow Byts/s'] = step * pack_size * result['Pkt Len Var'] / result['Flow Duration']
    return result


# In[72]:


connection_parser(example)


# In[22]:





# In[21]:





# In[ ]:




