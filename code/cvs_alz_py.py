######################################################
# Georgia Institute of Technology
# author: Hyojoon Kim
# date: 2010.12.7
#
# Network Device Configuration Analyzer CVS in Python
#
######################################################

import vlst_mod
import cmd_db
import sys
import re
import datetime
import time
import os
import MySQLdb as mdb
import difflib

######################################################
# * Dictionary structure (hash_dict)
#   (key_tuple):(value_lst)
#   
#   where,
#   * key_tuple = {file_name, date, version)
#   * value_lst = [ change_date                    (0)
#                   device_type(1=rtr,2=fw,3=swt)  (1)
#                   vendor                         (2)
#                   num_of_lines_device-mgt,       (3)
#                   num_of_lines_ARP,              (4)
#                   num_of_lines_VLAN,             (5)
#                   num_of_lines_IP_set,           (6)
#                   num_of_lines_routing,          (7)
#                   num_of_lines_ACL,              (8)
#                   num_of_lines_object_define,    (9)
#                   num_of_lines_self_sec,         (10)
#                   num_of_lines_lb                (11)
#                   num_of_lines_rt                (12)
#                   num_of_lines_ETC               (13)
#                   num_of_lines_garbage           (14)
#                   num_of_lines_Total_line        (15)
#                   change_of_lines_device-mgt,       (16)
#                   change_of_lines_ARP,              (17)
#                   change_of_lines_VLAN,             (18)
#                   change_of_lines_IP_set,           (19)
#                   change_of_lines_routing,          (20)
#                   change_of_lines_ACL,              (22)
#                   change_of_lines_object_define,    (22)
#                   change_of_lines_self_sec,         (23)
#                   change_of_lines_lb                (24)
#                   change_of_lines_rt                (25)
#                   change_of_lines_ETC               (26)
#                   change_of_lines_garbage           (27)
#                   change_of_lines_Total_line        (28)
#                   N/A                          (29)
#                   N/A                          (30)
#                   N/A                          (31)
#                 ]
######################################################

glb_hash_dict = {}
glb_head_dict = {}
hash_dict = {}

glb_count_lst = [0,0,0,0,0,0,0,0,0,0,0]
glb_change_lst = [0,0,0,0,0,0,0,0,0,0,0]

rtr_count_lst = [0,0,0,0,0,0,0,0,0,0,0]
rtr_change_lst = [0,0,0,0,0,0,0,0,0,0,0]

fw_count_lst = [0,0,0,0,0,0,0,0,0,0,0]
fw_change_lst = [0,0,0,0,0,0,0,0,0,0,0]

swt_count_lst = [0,0,0,0,0,0,0,0,0,0,0]
swt_change_lst = [0,0,0,0,0,0,0,0,0,0,0]

## Global variables
MAJOR_VER_SIZE = 10000

#### Get diff  ####
def get_diff(diff_gen, val_lst, v_name_str):
    mod_trig = 0
    cmd_type=0
    sline = ''

    for line in diff_gen:
        # check if add
        m_add = re.match(r'\+ .*',line)
        if m_add:
            sline = line.lstrip('+')
            cmd_type = check_command(sline, v_name_str, val_lst[vlst_mod.V_DTYPE])
            val_lst[vlst_mod.CHG_FIELD_ADD+cmd_type] = val_lst[vlst_mod.CHG_FIELD_ADD+cmd_type]+1
            if cmd_type!=vlst_mod.ADD_GBG:
               val_lst[vlst_mod.ADD_TOTAL] = val_lst[vlst_mod.ADD_TOTAL]+1
        else:
            # check if del
            m_del = re.match(r'- .*',line)
            if m_del:
                sline = line.lstrip('-')
                cmd_type = check_command(sline, v_name_str, val_lst[vlst_mod.V_DTYPE])
                val_lst[vlst_mod.CHG_FIELD_DEL+cmd_type] = val_lst[vlst_mod.CHG_FIELD_DEL+cmd_type]+1
                if cmd_type!=vlst_mod.DEL_GBG:
                    val_lst[vlst_mod.DEL_TOTAL] = val_lst[vlst_mod.DEL_TOTAL]+1
            else:
                # check if mod
                m_mod = re.match(r'! .*',line)
                if m_mod:
                    if mod_trig==1:
                        sline = line.lstrip('!')
                        cmd_type = check_command(sline, v_name_str, val_lst[vlst_mod.V_DTYPE])
                        val_lst[vlst_mod.CHG_FIELD_MOD+cmd_type] = val_lst[vlst_mod.CHG_FIELD_MOD+cmd_type]+1
                        if cmd_type!=vlst_mod.MOD_GBG:
                            val_lst[vlst_mod.MOD_TOTAL] = val_lst[vlst_mod.MOD_TOTAL]+1
                        mod_trig = 0;
                    else:
                        mod_trig = 1
                else:
                    # if all no, skip
                    continue
        if cmd_type==vlst_mod.N_ETC:
            pass
            #print 'change:'+sline

    # end of for loop
 
#### end of function #### 

#### Get stats  ####
def get_stats(stat_dir, fname_str):
    if len(hash_dict)==0:
        return

    dir_str = './' + stat_dir + '/' + fname_str
    os.mkdir(dir_str)
    
    stat1_f = open(dir_str+'/stat1.txt', 'w+')
    stat2_f = open(dir_str+'/stat2.txt', 'w+')
    stat3_f = open(dir_str+'/stat3.txt', 'w+')
   
    # lastest version
    keys = hash_dict.keys()
    key_lst = sorted(keys, key=lambda k: k[2])
    last_key = key_lst[-1]
    first_key = key_lst[0]

    value_lst = hash_dict.get(last_key)
 
    stat_str = 'Device-mgt ' + str(value_lst[0]) + '\n'
    stat_str = stat_str + 'ACL ' + str(value_lst[1]) + '\n'
    stat_str = stat_str + 'Interface ' + str(value_lst[2]) + '\n'
    stat_str = stat_str + 'Object-define ' + str(value_lst[3]) + '\n'
    stat_str = stat_str + 'QoS-inspect ' + str(value_lst[4]) + '\n'
    stat_str = stat_str + 'routing ' + str(value_lst[5]) + '\n'
    stat_str = stat_str + 'vlan ' + str(value_lst[6]) + '\n'
    stat_str = stat_str + 'ETC ' + str(value_lst[7]) + '\n'
    stat_str = stat_str + 'Total ' + str(value_lst[10]) + '\n'

    #for j in range(len(value_lst)):
    for j in range(11):
        glb_count_lst[j] = glb_count_lst[j] + value_lst[j]
        if value_lst[11]==1:
            rtr_count_lst[j] = rtr_count_lst[j] + value_lst[j]
        elif value_lst[11]==2:
            fw_count_lst[j] = fw_count_lst[j] + value_lst[j]
        elif value_lst[11]==3:
            swt_count_lst[j] = swt_count_lst[j] + value_lst[j]
    
    stat1_f.write(stat_str)
    print dir_str
    print value_lst

    # change
    change_lst = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    value_pre_lst = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    for k in key_lst:
        value_cur_lst = hash_dict.get(k)
        for i in range(10):
            change_lst[i] = change_lst[i] + abs(value_pre_lst[i]-value_cur_lst[i])
        value_pre_lst = value_cur_lst
    # end of loop 
    stat2_str = 'Device-mgt ' + str(change_lst[0]) + '\n'
    stat2_str = stat2_str + 'ACL ' + str(change_lst[1]) + '\n'
    stat2_str = stat2_str + 'Interface ' + str(change_lst[2]) + '\n'
    stat2_str = stat2_str + 'Object-define ' + str(change_lst[3]) + '\n'
    stat2_str = stat2_str + 'QoS-inspect ' + str(change_lst[4]) + '\n'
    stat2_str = stat2_str + 'routing ' + str(change_lst[5]) + '\n'
    stat2_str = stat2_str + 'vlan ' + str(change_lst[6]) + '\n'
    stat2_str = stat2_str + 'ETC ' + str(change_lst[7]) + '\n'
 
    j = 0
    for j in range(10):
        glb_change_lst[j] = glb_change_lst[j] + change_lst[j]
        if value_cur_lst[11]==1:
            rtr_change_lst[j] = rtr_change_lst[j] + change_lst[j]
        elif value_lst[11]==2:
            fw_change_lst[j] = fw_change_lst[j] + change_lst[j]
        elif value_lst[11]==3:
            swt_change_lst[j] = swt_change_lst[j] + change_lst[j]

    stat2_f.write(stat2_str)

    # Change timeline
    check_log_int = 0;
    now_day_int = first_key[1]

    if now_day_int==-1:
        check_log_int = check_log_int + 1
        tmp_key = key_lst[1]
        now_day_int = tmp_key[1]

    fval_lst = hash_dict.get(first_key)

    stat3_str = 't0 Device-mgt ACL Interface Object-define QoS-inspect routing vlan ETC Total\n'
    stat3_str = stat3_str + time.strftime("%a_%d_%b_%Y_%H:%M:%S_+0000", time.localtime(now_day_int))+' '+str(fval_lst[0])+' '+str(fval_lst[1])+' '+str(fval_lst[2])+' '+str(fval_lst[3])+' '+str(fval_lst[4])+' '+str(fval_lst[5])+' '+str(fval_lst[6])+' '+str(fval_lst[7])+' '+str(fval_lst[10])+'\n'

    cmp_day = time.localtime(now_day_int)
    h_diff = cmp_day.tm_hour 
    m_diff = cmp_day.tm_min
    s_diff = cmp_day.tm_sec

    # set hour,min,sec to 00.
    chk_int = now_day_int - (h_diff*3600 + m_diff*60 + s_diff)
    if len(key_lst)>1:

        nxt_key = key_lst[1+check_log_int]
        dbval_lst = fval_lst
        last_day = time.localtime(last_key[1])
        i = 1
        last = 0
    
        # iterate daily and check
        while chk_int <= last_key[1]:
            db_day = time.localtime(nxt_key[1])
            if nxt_key[1]==-1:
                if i<len(key_lst)-1:
                    i = i+1
                    nxt_key = key_lst[i]
                else:
                    last = 1
            elif (cmp_day.tm_year==db_day.tm_year) and (cmp_day.tm_mon==db_day.tm_mon) and (cmp_day.tm_mday==db_day.tm_mday):
                dbval_lst = hash_dict.get(nxt_key)
                if i<len(key_lst)-1:
                    i = i+1
                    nxt_key = key_lst[i]
                else:
                    last = 1
    
            if last==1:
                stat3_str = stat3_str + time.strftime("%a_%d_%b_%Y_%H:%M:%S_+0000", time.localtime(last_key[1]))+' '+str(dbval_lst[0])+' '+str(dbval_lst[1])+' '+str(dbval_lst[2])+' '+str(dbval_lst[3])+' '+str(dbval_lst[4])+' '+str(dbval_lst[5])+' '+str(dbval_lst[6])+' '+str(dbval_lst[7])+' '+str(dbval_lst[10])+'\n'
            else: 
                stat3_str = stat3_str + 't '+str(dbval_lst[0])+' '+str(dbval_lst[1])+' '+str(dbval_lst[2])+' '+str(dbval_lst[3])+' '+str(dbval_lst[4])+' '+str(dbval_lst[5])+' '+str(dbval_lst[6])+' '+str(dbval_lst[7])+' '+str(dbval_lst[10])+'\n'
        
            tmp1_day = time.localtime(nxt_key[1])
            tmp2_day = time.localtime(chk_int)
            if (tmp1_day.tm_year==tmp2_day.tm_year) and (tmp1_day.tm_mon==tmp2_day.tm_mon) and (tmp1_day.tm_mday==tmp2_day.tm_mday) and (i!=len(key_lst)-1):
                pass
            else:
                chk_int = chk_int + 3600*24
    
            cmp_day = time.localtime(chk_int)
            if cmp_day.tm_hour==23:
                chk_int = chk_int + 3600
                cmp_day = time.localtime(chk_int)
            elif cmp_day.tm_hour==1:
                chk_int = chk_int - 3600
                cmp_day = time.localtime(chk_int)
        # end of while
    stat3_f.write(stat3_str)

    stat1_f.close()
    stat2_f.close()
    stat3_f.close()
    return
#### end of function ####




#### For Juniper routers ####
def juniper_rtr_parser(whole_str):
    tmp_str = ''
    m1 = re.match(r'system {', whole_str)
    #if m1:
    #    tmp_str = 




#### end of function ####

#### Identify and classify command ####
def check_command(line_str, v_name_str, v_type):
    cmd_type_int = -1  # int identifier of type of command
    re_m1_1_2_str = 'GARBAGEGARBAGEGARBAGE'
    # check if comment or useless
    m1 = re.match(r'\s*(!.*)|(:.*)|(@.*)|(#.*)|(;.*)|(\n)', line_str)
    if m1:
        cmd_type_int = vlst_mod.N_GBG

        return cmd_type_int

    # check if null
    if line_str=='' or line_str=='\s+' or line_str==' ':
        cmd_type_int = vlst_mod.N_GBG
        return cmd_type_int

    # Cisco
    if (v_name_str=='cisco') or (v_name_str=='cisco-cat') or (v_name_str=='cisco-nx'):
        if v_type==1: # router
            # device_mgt
            re_m1_1_str = cmd_db.CMDMAP_CISCO_RTR_MGT
            # layer 1
            re_m1_2_str = cmd_db.CMDMAP_CISCO_RTR_L1
            # Layer 2
            re_m2_1_str = cmd_db.CMDMAP_CISCO_RTR_L2
            # Layer 2.5 - vlan
            re_m2_2_str = cmd_db.CMDMAP_CISCO_RTR_VLAN
            # Layer 3 - switching
            re_m2_3_str = cmd_db.CMDMAP_CISCO_RTR_L3_S
            # Layer 3 - routing
            re_m2_4_str = cmd_db.CMDMAP_CISCO_RTR_L3_R
            # ACL
            re_m3_1_str = cmd_db.CMDMAP_CISCO_RTR_ACL
            # Security 
            re_m3_1_2_str = cmd_db.CMDMAP_CISCO_RTR_SEC
            # control filtering
            re_m3_2_str = cmd_db.CMDMAP_CISCO_RTR_C_FLT
            # Services - QoS
            re_m3_3_str = cmd_db.CMDMAP_CISCO_RTR_QOS
            # Garbage
            re_m4_str = cmd_db.CMDMAP_CISCO_RTR_GBG
            #
        #re_m1_1_str = '\s*((set )*([(no )]*((errdisable)|(password)|(power)|(web-management)|(include-credentials)|(fastboot)|(console )|(time )|(timesync)|(dhcp-snooping)|(sntp )|(module)|(fault-finder)|(tacacs)(password)|(ntp )|(redundancy)|(snmp-server)|(tacacs-server)|(line con)|(line vty)|(line aux)|(logging)|(pager)|(mtu)|(ssh)|(aaa)|(monitor-interface)|(icmp)|(asdm)|(arp timeout)|(timeout)|(aaa-server)|(key)|(username)|(http)|(telnet)|(tftp-server)|(firewall)|(terminal)|(hostname)|(domain-name)|(enable)|(names)|(dns-guard)|(passwd)|(banner)|(adm)|(fragment)|(nameif)|(pdm)|(floodguard)|(service)|(boot)|(boot-start-marker)|(boot-end-marker)|(clock)|(buffers)|(negotiation auto)|(cdp enable)|(hold-queue))(.)*)|([(no )]*ip ((redirects)|(unreachables)|(directed-broadcast)|(proxy-arp)|(domain-name)|(subnet-zero)|(finger)|(name-server)|(ssh)|(multicast-routing)|(source-route)|(bootp)|(multicast)|(tacacs)|(authorized-managers)|(flow-capture)|(flow-export)|(http))(.)*|([no ]*mls (.)*)|(fabric switching-mode(.)*)|(diagnostic (.)*))|(\s*(no )*snmp trap link-status)|(event manager (.)*)|(switch \d+)|(system mtu))'
            #re_m1_1_2_str = '\s*(no )*((privilege )|(failover)|(ftp mode )|(mac-address )|(sysopt ))'
            # layer 1
            #re_m1_2_str = '\s*([(no )]*((description (.)*)|(interface (.)*)|(\s+switchport)|(\s+shutdown)|(\s+channel-group (.)*)|(\s*allocate-interface )))'
            # Layer 2
            #re_m2_1_str = '\s*(arp (\d)+\.(\d)+\.(\d)+\.(\d)+(.)*ARPA)|([(no )]*((\s*spanning-tree)))' 
            # Layer 2.5 - vlan
            #re_m2_2_str = '\s*(vtp )|(\s*interface Vlan\w+)|(\s*set ((trunk)|(vlan)) [\s\w]+)|(\s*vlan (.)+)|(\s*switchport trunk )|(\s*switchport mode trunk)|((\s)*switchport access vlan )|(vmps server )'
            # Layer 3 - switching
            #re_m2_3_str = '\s*([(no )]*((route outside)|(route inside)|(\s*ip address)|(\s*ip classless)|(\s*ip route)|(\s*ip default-gateway)|(\s*vc-class))(.)*)|(\s*static \()'
            # Layer 3 - routing
            #re_m2_4_str = '\s*([(no )]*((router ospf)|(router isis)|(router bgp)|(router rip)|(neighbor)|(route-map)|(network)|(ip ospf)|(ip as-path)) (.)*)'
            # ACL
            #re_m3_1_str = '\s*((\s*object-group)|(\s*network-object)|(\s*group-object)|(\s*port-object) [\s\w]*)|(\s*(ip )*((access-list)|(access-group))[\s\w]*)|(context )|(config-url )|(name \d+\.\d+\.\d+\.\d+)'
            # Security 
            #re_m3_1_2_str = '\s*(no )*((\s*tunnel-group )|(\s*crypto )|(\s*dynamic-access-policy-record)|(\s*same-security-traffic )|(\s*ip local pool vpn-pool )|(\s*threat-detection )|(\s*webvpn)|(\s*group-policy))'
            # control filtering
            #re_m3_2_str = '\s*((prefix-list)) [\s\w]*'
            # Services - QoS
            #re_m3_3_str = '\s*[(no )]*((\s*class-map)|(\s*policy-map)|(\s*service-policy)|(\s*fixup)|(\s*inspect)|(\s*instrumentation monitor)|(\s*class)) (.)*'
            # Garbage
            #re_m4_str = '\s*(((FWSM [\s\w]*)|(\s*config-register)|(\s*Cryptochecksum:))(.)*)|(\s*exit)|(\s*ASA Version )|(\s*PIX Version )|(\s*ipv6 )'
        
        elif v_type==2: # firewall
            # device_mgt
            re_m1_1_str = cmd_db.CMDMAP_CISCO_FW_MGT
            # layer 1
            re_m1_2_str = cmd_db.CMDMAP_CISCO_FW_L1
            # Layer 2
            re_m2_1_str = cmd_db.CMDMAP_CISCO_FW_L2
            # Layer 2.5 - vlan
            re_m2_2_str = cmd_db.CMDMAP_CISCO_FW_VLAN
            # Layer 3 - switching
            re_m2_3_str = cmd_db.CMDMAP_CISCO_FW_L3_S
            # Layer 3 - routing
            re_m2_4_str = cmd_db.CMDMAP_CISCO_FW_L3_R
            # ACL
            re_m3_1_str = cmd_db.CMDMAP_CISCO_FW_ACL
            # Security 
            re_m3_1_2_str = cmd_db.CMDMAP_CISCO_FW_SEC
            # control filtering
            re_m3_2_str = cmd_db.CMDMAP_CISCO_FW_C_FLT
            # Services - QoS
            re_m3_3_str = cmd_db.CMDMAP_CISCO_FW_QOS
            # Garbage
            re_m4_str = cmd_db.CMDMAP_CISCO_FW_GBG

        elif v_type==3: # switch
            # device_mgt
            re_m1_1_str = cmd_db.CMDMAP_CISCO_SWT_MGT
            re_m1_1_2_str = cmd_db.CMDMAP_CISCO_SWT_MGT_2 
            # layer 1
            re_m1_2_str = cmd_db.CMDMAP_CISCO_SWT_L1
            # Layer 2
            re_m2_1_str = cmd_db.CMDMAP_CISCO_SWT_L2
            # Layer 2.5 - vlan
            re_m2_2_str = cmd_db.CMDMAP_CISCO_SWT_VLAN
            # Layer 3 - switching
            re_m2_3_str = cmd_db.CMDMAP_CISCO_SWT_L3_S
            # Layer 3 - routing
            re_m2_4_str = cmd_db.CMDMAP_CISCO_SWT_L3_R
            # ACL
            re_m3_1_str = cmd_db.CMDMAP_CISCO_SWT_ACL
            # Security 
            re_m3_1_2_str = cmd_db.CMDMAP_CISCO_SWT_SEC
            # control filtering
            re_m3_2_str = cmd_db.CMDMAP_CISCO_SWT_C_FLT
            # Services - QoS
            re_m3_3_str = cmd_db.CMDMAP_CISCO_SWT_QOS
            # Garbage
            re_m4_str = cmd_db.CMDMAP_CISCO_SWT_GBG

        else:
            print 'Wrong device type.'

    # HP. 
    elif v_name_str=='hp-procurve':
        # no router or firewall for GT. 
        if v_type==3: # switch
            # device_mgt
            re_m1_1_str = cmd_db.CMDMAP_HP_SWT_MGT
            # layer 1
            re_m1_2_str = cmd_db.CMDMAP_HP_SWT_L1
            # Layer 2
            re_m2_1_str = cmd_db.CMDMAP_HP_SWT_L2
            # Layer 2.5 - vlan
            re_m2_2_str = cmd_db.CMDMAP_HP_SWT_VLAN
            # Layer 3 - switching
            re_m2_3_str = cmd_db.CMDMAP_HP_SWT_L3_S
            # Layer 3 - routing
            re_m2_4_str = cmd_db.CMDMAP_HP_SWT_L3_R
            # ACL
            re_m3_1_str = cmd_db.CMDMAP_HP_SWT_ACL
            # Security 
            re_m3_1_2_str = cmd_db.CMDMAP_HP_SWT_SEC
            # control filtering
            re_m3_2_str = cmd_db.CMDMAP_HP_SWT_C_FLT
            # Services - QoS
            re_m3_3_str = cmd_db.CMDMAP_HP_SWT_QOS
            # Garbage
            re_m4_str = cmd_db.CMDMAP_HP_SWT_GBG
        else:
            print 'Wrong device type.'

#        re_m1_1_str = '\s*([(no )]*((errdisable)|(password)|(power)|(web-management)|(include-credentials)|(fastboot)|(console )|(time )|(timesync)|(dhcp-snooping)|(sntp )|(module)|(fault-finder)|(tacacs)(password)|(ntp )|(redundancy)|(snmp-server)|(tacacs-server)|(line con)|(line vty)|(line aux)|(logging)|(pager)|(mtu)|(ssh)|(aaa)|(monitor-interface)|((ip )*icmp)|(asdm)|(arp timeout)|(timeout)|(aaa-server)|(key)|(username)|(http)|(telnet)|(tftp server)|(firewall)|(terminal)|(hostname)|(domain-name)|(enable)|(names)|(dns-guard)|(passwd)|(banner)|(fragment)|(nameif)|(floodguard)|(service)|(boot)|(boot-start-marker)|(boot-end-marker)|(clock)|(buffers)|(negotiation auto)|(cdp enable)|(hold-queue))(.)*)|([(no )]*ip ((redirects)|(unreachables)|(directed-broadcast)|(proxy-arp)|(domain-name)|(subnet-zero)|(finger)|(name-server)|(ssh)|(multicast-routing)|(source-route)|(bootp)|(multicast)|(tacacs)|(authorized-managers)|(flow-capture)|(flow-export)|(http)|(dns ))(.)*|([no ]*mls (.)*))|(\s*(no )*snmp trap link-status)|(event manager (.)*)|(radius-server (.)*)|(arp-protect(.)*)|(snmpv3 .*)(switch \d+)|(system mtu)'
#        # layer 1
#        re_m1_2_str = '\s*([(no )]*((description (.)*)|(interface (.)*)|(\s*speed-duplex)|(\s+switchport)|(\s+shutdown)|(\s+channel-group (.)*)))'
#        # Layer 2
#        re_m2_1_str = '\s*(arp (\d)+\.(\d)+\.(\d)+\.(\d)+(.)*ARPA)|([(no )]*((spanning-tree)))' 
#        # Layer 2.5 - vlan
#        re_m2_2_str = '\s*(vtp )|(interface Vlan\w+)|(set ((trunk)|(vlan)) [\s\w]+)|(vlan (.)+)|(switchport trunk )|(switchport mode trunk)|((\s)*switchport access vlan )|(\s+name )|(\s+[no ]*[un]*tagged )|(\s+ip access-group .* vlan)|(vmps server )'
#        # Layer 3 - switching
#        re_m2_3_str = '\s*([(no )]*((route outside)|(route inside)|(ip address)|(ip classless)|(ip route)|(ip default-gateway)|(vc-class))(.)*)'
#        # Layer 3 - routing
#        re_m2_4_str = '\s*([(no )]*((router ospf)|(router isis)|(router bgp)|(router rip)|(neighbor)|(route-map)|(network)|(ip ospf)|(ip as-path)) (.)*)'
#        # ACL
#        re_m3_1_str = '\s*((object-group)|(\s*network-object)|(\s*group-object)|(\s*port-object) [\s\w]*)|([(ip )]*((access-list)|(access-group)) [\d\s\w]*)|(\s+[\d* ]*permit .*)|(\s+[\d* ]*deny .*)'
#        # control filtering
#        re_m3_2_str = '\s*((prefix-list)) [\s\w]*'
#        # Services - QoS
#        re_m3_3_str = '\s*[(no )]*((class-map)|(policy-map)|(service-policy)|(fixup)|(inspect)|(instrumentation monitor)|((no )*qos)|(class)|(policy qos)|(\s+rate-limit)|(\s+\d+ ignore)|(\s+\d+ match)|(\s+\d+ class)) (.)*'
#        # Garbage
#        re_m4_str = '\s*(((FWSM [\s\w]*)|(config-register)|(Cryptochecksum:))(.)*)|(\s*exit)|(\n+)|( \n+)|()'

    else:
        print 'No parser for this Vendor: '+v_name_str
    # Device Setting
    #m1_1 = re.match(r'([(no )]*((errdisable)|(password)|(power)|(web-management)|(include-credentials)|(fastboot)|(console )|(time )|(timesync)|(dhcp-snooping)|(sntp )|(module)|(fault-finder)|(tacacs)(password)|(ntp )|(redundancy)|(snmp-server)|(tacacs-server)|(line con)|(line vty)|(line aux)|(logging)|(pager)|(mtu)|(ssh)|(aaa)|(monitor-interface)|(icmp)|(asdm)|(arp timeout)|(timeout)|(aaa-server)|(key)|(username)|(http)|(telnet)|(tftp-server)|(firewall)|(terminal)|(hostname)|(domain-name)|(enable)|(names)|(dns-guard)|(passwd)|(banner)|(route outside)|(route inside)|(adm)|(fragment)|(nameif)|(pdm)|(floodguard)|(service)|(boot)|(boot-start-marker)|(boot-end-marker)|(clock)|(buffers)|(negotiation auto)|(cdp enable)|(hold-queue))(.)*)|([(no )]*ip ((redirects)|(unreachables)|(directed-broadcast)|(proxy-arp)|(domain-name)|(subnet-zero)|(finger)|(name-server)|(ssh)|(multicast-routing)|(source-route)|(bootp)|(multicast)|(tacacs)|(authorized-managers))(.)*)', line_str) 
 
    m1_1 = re.match(re_m1_1_str, line_str)
    if m1_1:
        cmd_type_int = vlst_mod.N_DEV_MGT
        return cmd_type_int

    m1_1_2 = re.match(re_m1_1_2_str, line_str)
    if m1_1_2:
        cmd_type_int = vlst_mod.N_DEV_MGT
        return cmd_type_int

    # Topology L1
    m1_2 = re.match(re_m1_2_str, line_str)
    if m1_2:
        cmd_type_int = vlst_mod.N_L1
        return cmd_type_int

    m2_1 = re.match(re_m2_1_str, line_str)
    if m2_1:
        cmd_type_int = vlst_mod.N_L2
        return cmd_type_int
    ## L2.5 - VLAN
    #m2_2 = re.match(r'(vtp )|(interface Vlan\w+)|(set ((trunk)|(vlan)) [\s\w]+)|(vlan (.)+)|(switchport trunk )|(switchport mode trunk)|((\s)*switchport access vlan )', line_str) 
    m2_2 = re.match(re_m2_2_str, line_str)
    if m2_2:
        cmd_type_int = vlst_mod.N_VLAN
        return cmd_type_int
    ## L3 - IP, route setting for each device
    #m2_3 = re.match(r'([(no )]*((description )|(spanning-tree)|(route outside)|(route inside)|(ip address)|(ip classless)|(ip route)|(ip default-gateway)|(vc-class))(.)*)|(interface (.)*)', line_str) 
    m2_3 = re.match(re_m2_3_str, line_str)
    if m2_3:
        cmd_type_int = vlst_mod.N_L3_S
        return cmd_type_int
    ## L3 - Routing
    #m2_4 = re.match(r'([(no )]*((router ospf)|(router isis)|(router bgp)|(router rip)|(neighbor)|(route-map)|(network)|(ip ospf)|(ip as-path)) (.)*)', line_str) 
    m2_4 = re.match(re_m2_4_str,line_str)
    if m2_4:
        cmd_type_int = vlst_mod.N_L3_RTR
        return cmd_type_int

    # Policy
    ## ACLs
    #m3_1 = re.match(r'[(ip )]*((access-list)|(access-group)|(prefix-list)) [\s\w]*', line_str)
    m3_1 = re.match(re_m3_1_str,line_str)
    if m3_1:
        cmd_type_int = vlst_mod.N_ACL
        return cmd_type_int
    
    m3_1_2 = re.match(re_m3_1_2_str,line_str)
    if m3_1_2:
        cmd_type_int = vlst_mod.N_SEC
        return cmd_type_int

    ## object-group
    #m3_2 = re.match(r'((object-group)|(network-object)|(port-object)) [\s\w]*', line_str)
    m3_2 = re.match(re_m3_2_str,line_str)
    if m3_2:
        cmd_type_int = vlst_mod.N_C_FLT
        return cmd_type_int
    ## Self_sec. QoS, inspect, etc
    #m3_3 = re.match(r'[(no )]*((class-map)|(policy-map)|(service-policy)|(fixup)|(inspect)|(instrumentation monitor)) (.)*', line_str)
    m3_3 = re.match(re_m3_3_str,line_str)
    if m3_3:
        cmd_type_int = vlst_mod.N_QOS
        return cmd_type_int
    ## Loadbalance
    #m3_4 = re.match(r'instrumentation monitor (.)*', line_str)
    #if m3_4:
    #    cmd_type_int = vlst_mod.N_LB
    #    return cmd_type_int
    ## Ratelimit
    #m3_5 = re.match(r'instrumentation monitor (.)*', line_str)
    #if m3_5:
    #    cmd_type_int = vlst_mod.N_RT
    #    return cmd_type_int
    
    # Garbage
    #m4 = re.match(r'(((FWSM [\s\w]*)|(config-register)|(Cryptochecksum:))(.)*)|(exit)', line_str)
    m4 = re.match(re_m4_str,line_str)
    if m4:
        cmd_type_int = vlst_mod.N_GBG
        return cmd_type_int

    # if the process came this far, it is etc.
    cmd_type_int = vlst_mod.N_ETC
    print line_str

    return cmd_type_int
#### end of function ####

#### Inspect Juniper configuration ####
def inspect_juniper(config_str, val_lst, v_name_str):
    bkt_cnt = 0
    tmp_str = ''
    m1 = re.match(r'system {', config_str)
    if m1: 
        sys_start_index = m1.end()
        tmp_str = config_str[sys_start_index:]

    while True:
        find_bkt = re.search('{\n', tmp_str)
        if find_bkt:
            bkt_cnt = bck_cnt + 1
            start_idx = find_bkt.end()
            tmp_str = tmp_str[start_idx:]
        find_end_bkt = re.search('}\n', tmp_str)
        if find_end_bkt:
            bkt_cnt = bck_cnt - 1
            start_idx = find_bkt.end()
            tmp_str = tmp_str[start_idx:]
        if bkt_cnt==0:
            break

    # TODO
    return val_lst
#### end of function ####

#### Inspect configuration ####
def inspect_config(config_str, val_lst, v_name_str):
    if v_name_str=='juniper':
        val_lst = inspect_juniper(config_str, val_lst, v_name_str)
    else:
        lstlines = config_str.splitlines()
        num_entry_int = len(lstlines)
        i = 0
        cmd_type = -1
        total_lines = 0
    
        while i < num_entry_int-1:
            # check if comment
            #m1 = re.match(r'(!.*)|(:.*)|(@.*)|(#.*)', lstlines[i])
            m1 = re.match(r'(!.*)|(:.*)|(@.*)|(#.*)|(;.*)', lstlines[i])
            if m1:
                i = i+1
                continue
            else:
                # check what the line is.
                cmd_type = check_command(lstlines[i], v_name_str, val_lst[vlst_mod.V_DTYPE])
                # determine type of device (switch, firewall, or router)
                #if cmd_type==vlst_mod.N_ACL:
                #if cmd_type==vlst_mod.N_OBJ_DEF:
                #    val_lst[vlst_mod.V_DTYPE]=2
                #elif cmd_type==vlst_mod.N_L3_RTR:
                #elif cmd_type==vlst_mod.N_RTR:
                #    val_lst[vlst_mod.V_DTYPE]=1
    
                val_lst[cmd_type] = val_lst[cmd_type]+1
                total_lines = total_lines + 1
        
                # check if next line starts with whitespace: means embeded command.
#                m1 = re.match(r'\s+', lstlines[i+1])
#                if m1:
#                    if cmd_type!=vlst_mod.N_L1:
#                    #if cmd_type!=vlst_mod.N_IP_SET:
#                        val_lst[cmd_type] = val_lst[cmd_type]+1
#                        total_lines = total_lines + 1
#    
#                        while 1:
#                            i = i + 1
#                            m2 = re.match(r'\s+', lstlines[i+1])
#                            if m2:
#                                val_lst[cmd_type] = val_lst[cmd_type]+1
#                                total_lines = total_lines + 1
#                                continue
#                            else:
#                                break
#                else:
#                    pass
    
            i = i + 1
        # end of while
        
        val_lst[vlst_mod.N_TOTAL] = total_lines


    return val_lst
#### end of function ####

#### Get changelog function ####
def get_change(txt_str, whole_str,val_lst, v_name_str):

    ###### Rule of understanding RCS diffs ############
    # 1. Added: a[num_a], followed by a configuration #
    # 2. Deleted: d[num_a], follwed by nothing        #
    # 3. Modified: d[num_a], followed by a[num_b],    #
    #              where num_a == num_b               #
    #                                                 #
    #  * Keep in mind: in this program, add and       #
    #    delete representation is reversed, so it is  #
    #    opposite from above. This isbecause the      #
    #    latest (i.e. head) version has the whole     #
    #    configuration, not the first version.        #  
    ###################################################

    i = 0
    del_cnt = 0
    adapt_int = 0
    now_conf_str = whole_str
    tmp_conf_str = now_conf_str
    lstlines = txt_str.splitlines()
    #who_lstlines = whole_str.splitlines()
    now_lstlines = now_conf_str.splitlines()
    tmp_lstlines = tmp_conf_str.splitlines()
    num_entry_int = len(lstlines)
    content_str = ''
    #cmd_type = -1

    while i < num_entry_int-1:
        # get line (add or delete)
        match1 = re.search(r'd(\d*) (\d*)', lstlines[i])
        if match1:
            # it is a delete. However, it is an add, if time goes forward.
            #print 'it is a delete'
            del_cnt = range(int(match1.group(2)))
            for j in del_cnt:
                #now_lstlines[int(match1.group(1))+j-1] = ''
                #cmd_type = check_command(now_lstlines[int(match1.group(1))-1+adapt_int], v_name_str)
                #val_lst[vlst_mod.CHG_FIELD_ADD+cmd_type] = val_lst[vlst_mod.CHG_FIELD_ADD+cmd_type]+1
                #val_lst[vlst_mod.CH_TOTAL] = val_lst[vlst_mod.CH_TOTAL] + 1
                #print now_lstlines[292]
                #print now_lstlines[293]
                #print now_lstlines[294]
                #print now_lstlines[295]
                now_lstlines.pop(int(match1.group(1))-1+adapt_int)
                #tmp_lstlines.pop(int(match1.group(1))+j-1+adapt_int)
            adapt_int = adapt_int - int(match1.group(2))
            i = i + 1
        else:
            match1 = re.search(r'a(\d*) (\d*)', lstlines[i])
            if match1:
                # it is an add. However, it is a delete, if time goes forward.
                #print 'it is an add'
                for j in range(int(match1.group(2))):
                    #cmd_type = check_command(now_lstlines[int(match1.group(1))+j+adapt_int], v_name_str)
                    #val_lst[vlst_mod.CHG_FIELD_ADD+cmd_type] = val_lst[vlst_mod.CHG_FIELD_ADD+cmd_type]+1
                    #val_lst[vlst_mod.CH_TOTAL] = val_lst[vlst_mod.CH_TOTAL] + 1
                    now_lstlines.insert(int(match1.group(1))+j+adapt_int, lstlines[i+j+1])
                    #print now_lstlines[int(match1.group(1))+j+adapt_int]
                    #print now_lstlines[295]
                    #if now_lstlines[int(match1.group(1))+j-1] == '':
                    #    now_lstlines[int(match1.group(1))+j-1] = lstlines[i+j+1]
                    #else:
                    #    now_lstlines.insert(int(match1.group(1))+j, lstlines[i+j+1])
                adapt_int = adapt_int + int(match1.group(2))
                i = i + 1 + int(match1.group(2))
            else:
               if lstlines[i]=='@':
#                   print 'done'
                   adapt_int = 0
#                   for k in now_lstlines:
#                       if k=='':
#                           now_lstlines.remove(k)
#                           print 'yaya'
               break
    # end of while

#            if match1.group(1)=='d':
#                # check if next line is add.
#                match2 = re.search(r'a(\d*) (\d*)', lstlines[i+1])
#                if match2:
#                    if match2.group(1)==match1.group(2):
#                        # it is a modification
#                        print 'it is a modification'
#                        content_str = lstlines[i+2]
#                        #print content_str
#                        i = i + 3
#                    else: 
#                        pass
#                else:
#                    # it is a delete. However, it is an add, if time goes forward.
#                    print 'it is a delete'
#                    for j in range(int(match1.group(3))):
#                        now_lstlines.pop(int(match1.group(2))+j-1)
#
#                    i = i + 1
#            elif match1.group(1)=='a':
#                # it is an add
#                print 'it is an add'
#                content_str = lstlines[i+1]
#                #print content_str
#                #print 'i isisisis ' + str(i)
#                i = i + 2
#            else: 
#                pass
#        else:
#            if lstlines[i]=='@':
#                print 'done'
#            break

    curr_conf_str = ''
    for i in now_lstlines:
        curr_conf_str = curr_conf_str+i+'\n'

    return curr_conf_str
#### end of function ####

#### Get change date function ####
def get_date_2(date_str):
    date_str = date_str.lstrip("@")
    m1 = re.search(r'([\d]+)/([\d]+)/([\d]+)', date_str)
    if date_str=='*** empty log message ***':
        print 'Empty date string. Return -1 for date'
        return -1
    elif m1:
        date_epoch = time.strptime(date_str, "%m/%d/%Y")
    else:
        date_epoch = time.strptime(date_str, "%a %b %d %H:%M:%S %Z %Y")
    
    return time.mktime(date_epoch)
#### end of function ####


#### Get change date function ####
def get_date(date_str):
    date_str = date_str.lstrip("@")
    m1 = re.search(r'([\d]+)/([\d]+)/([\d]+)', date_str)
    if date_str=='*** empty log message ***':
        print 'Empty date string. Return -1 for date'
        return -1
    elif m1:
        date_epoch = time.strptime(date_str, "%m/%d/%Y")
    else:
        date_epoch = time.strptime(date_str, "%a %b %d %H:%M:%S %Z %Y")
    
    return time.mktime(date_epoch)
#### end of function ####

#### Extract function ####
def extract_lines_2(arg_file, file_name, device_type):
    tmp_dict = {}
    state_dict = {}
    key_lst = []
    val_lst = []
    prev_val_lst = []
    version_int = 0
    vendor_name_str=''
    
    for i in range(vlst_mod.LIST_SIZE):
        val_lst.append(0)
    val_lst[vlst_mod.V_DTYPE] = int(device_type)
    val_lst[vlst_mod.V_VENDOR] = ' '

    #val_lst = vlst_mod.create(tmp_lst)

    content_str = arg_file.read()
    tmp_str = content_str

    # get filename, without the whole path.
    f_idx = file_name.rfind('/') + 1
    fname_str = file_name[f_idx:]

    # search for head version
    match = re.search(r'head\t(\d*)\.(\d*);', content_str)
    if match:
        major_ver_str = match.group(1)
        minor_ver_str = match.group(2)
        head_version_str =  major_ver_str + "." + minor_ver_str
        version_str = head_version_str
        version_int = int(major_ver_str) * MAJOR_VER_SIZE + int(minor_ver_str)
        head_version_int = version_int

        # advance tmp_str
        start_idx = match.end()
        tmp_str = tmp_str[start_idx:]
    else:
        print 'Cannot find head version!'
        print file_name

    # Preprocess
    while version_int >= (1*MAJOR_VER_SIZE+1):
    # Search for date
        search_str = version_str + '\ndate\t([\d]+\.[\d]+\.[\d]+\.[\d]+\.[\d]+\.[\d]+);\tauthor [\w]+;\tstate (\w+)'
        match = re.search(search_str, tmp_str)
        if match:
            # get date and state
            date_str = match.group(1)
            date_epoch = time.strptime(date_str, "%Y.%m.%d.%H.%M.%S")
            timestamp_sec = time.mktime(date_epoch) + time.timezone
            state_str = match.group(2)

            # Make tuple - key for dictionary
            key_tuple = fname_str, version_int, timestamp_sec
            key_lst.append(key_tuple)
            state_dict[key_tuple] = state_str

            # update to previous version
            version_int = version_int-1
            version_str = '1.' + str(version_int % MAJOR_VER_SIZE)

            # advance tmp_str
            start_idx = match.end()
            tmp_str = tmp_str[start_idx:]
        else:
            print 'Failed to get date string'
            break
    # end of while loop
    
    # recover version string and int
    version_str = head_version_str
    version_int = head_version_int

    key_lst_idx = 0

    while version_int >= (1*MAJOR_VER_SIZE+1):
        # initialize
        v_name = val_lst[vlst_mod.V_VENDOR]
        v_type = val_lst[vlst_mod.V_DTYPE]
        val_lst=[]
        for i in range(vlst_mod.LIST_SIZE):
            val_lst.append(0)

        # preserve some data
        val_lst[vlst_mod.V_VENDOR] = v_name
        val_lst[vlst_mod.V_DTYPE] = v_type

        search_str = version_str + '\nlog\n@.*\n@.*\ntext\n@'
        m1 = re.search(search_str, tmp_str)
        if m1:
            start_text_idx = m1.end()
            tmp_str = tmp_str[start_text_idx:]

            pre_ver_int = version_int-1
            pre_ver_str = '1.' + str(pre_ver_int % MAJOR_VER_SIZE)

            # search for text end.
            search_str = pre_ver_str + '\nlog\n'
            m2 = re.search(search_str,tmp_str)
            if m2:
                end_text_int = m2.start()
                txt_for_ver_str = tmp_str[:end_text_int]
            else: 
                txt_for_ver_str = tmp_str

            # if head version, just get the whole text
            if version_str==head_version_str:
                whole_config_str = txt_for_ver_str
                # if juniper, for now, just skip. TODO
                tmpm1 = re.search(r'# RANCID-CONTENT-TYPE: juniper', whole_config_str)
                if tmpm1:
                    break

                # get vendor
                m_vendor = re.search(r'RANCID-CONTENT-TYPE: (.*)\n', whole_config_str)
                if m_vendor:
                    vendor_name_str = m_vendor.group(1)
                    if (vendor_name_str!='cisco') and (vendor_name_str!='cisco-cat') and (vendor_name_str!='cisco-nx') and (vendor_name_str!='hp-procurve'):
                        break
                    else:
                        val_lst[vlst_mod.V_VENDOR] = vendor_name_str

                else:
                    break

                # inspect config string
                val_lst = inspect_config(whole_config_str, val_lst, vendor_name_str)
                # put to global hash dictionary
                key_tuple = key_lst[key_lst_idx]
                val_lst[vlst_mod.STATE] = state_dict[key_tuple]
                glb_hash_dict[key_tuple] = val_lst
                # put to global head dictionary
                glb_head_dict[fname_str] = head_version_int
                #glb_hash_dict.setdefault(key_tuple, val_lst)
                #hash_dict.setdefault(key_tuple, val_lst)
                # save current configuration string, for later usage by changelog
                prev_config_str = whole_config_str
                prev_val_lst = val_lst
                prev_key_tuple = key_tuple

            # else, go through changelog, and produce text
            else:
                curr_config_str = get_change(txt_for_ver_str, prev_config_str,val_lst, vendor_name_str)

                # Get context diff
                prev_config_lst = prev_config_str.splitlines()
                curr_config_lst = curr_config_str.splitlines()
                context_diff_str = difflib.context_diff(curr_config_lst, prev_config_lst)
                get_diff(context_diff_str, prev_val_lst, vendor_name_str)
                # update previous dict entry
                tmp_dict.clear()
                tmp_dict[prev_key_tuple] = prev_val_lst
                glb_hash_dict.update(tmp_dict)

                val_lst = inspect_config(curr_config_str,val_lst, vendor_name_str)
                #hash_dict.setdefault(key_tuple, val_lst)
                key_tuple = key_lst[key_lst_idx]
                val_lst[vlst_mod.STATE] = state_dict[key_tuple]
                glb_hash_dict[key_tuple] = val_lst
                
                # preserve    
                prev_val_lst=[]
                for j in range(vlst_mod.LIST_SIZE):
                    prev_val_lst.append(0)
                prev_val_lst = val_lst
                prev_config_str = curr_config_str
                prev_key_tuple = key_tuple

            # update to previous version
            version_int = pre_ver_int
            version_str = pre_ver_str

        else: 
            print 'Cannot find log and text:'
            print file_name
            break

        key_lst_idx = key_lst_idx + 1
    # end of while loop
    #
    
#    # Start extracting text from RCS file
#    while version_int >= (1*MAJOR_VER_SIZE+1):
#        v_name = val_lst[vlst_mod.V_VENDOR]
#        v_type = val_lst[vlst_mod.V_DTYPE]
#        val_lst=[]
#        i=0
#        for i in range(vlst_mod.LIST_SIZE):
#            val_lst.append(0)
#        val_lst[vlst_mod.V_VENDOR] = v_name
#        val_lst[vlst_mod.V_DTYPE] = v_type
#
#        # Search for date
#        search_str = version_str + '\nlog\n'
#        match = re.search(search_str, tmp_str)
#        if match:
#            start_index = match.end()
#            tmp_str = tmp_str[start_index:]
#        match2 = re.search('@.*\n', tmp_str)
#        if match2: 
#            date_str =  match2.group(0).strip('\n')
#            new_date_int = get_date(date_str)
#  
#        val_lst[vlst_mod.V_DATE] = new_date_int
#
#        # Make tuple - key for dictionary
#        key_tuple =  fname_str, version_int
#        #key_tuple =  fname_str, new_date_int, version_int
#        
#        # search for text
#        search_str = '@\ntext\n@'
#        match3 = re.search(search_str, tmp_str)
#
#        if match3:
#            start_text_int = match3.end()
#            tmp_str = tmp_str[start_text_int:]
#    
#            # if head version, it is the whole configuration.
#            # else, it is changelogs
#            if version_str==head_version_str:
#                is_head_ver_int = 1
#            else:
#                is_head_ver_int = 0
#    
#            tmp_ver_int = int(minor_ver_str)-1
#            minor_ver_str = str(tmp_ver_int)
#            version_str = major_ver_str + "." + str(tmp_ver_int)
#            version_int = int(major_ver_str) * MAJOR_VER_SIZE + int(minor_ver_str)
#    
#            # search for text end.
#            search_str = version_str + '\nlog\n'
#            match4 = re.search(search_str,tmp_str)
#            if match4:
#                end_text_int = match4.start()
#                txt_for_ver_str = tmp_str[:end_text_int]
#            else: 
#                txt_for_ver_str = tmp_str
#            if is_head_ver_int==1:
#                whole_config_str = txt_for_ver_str
#                # if juniper, for now, just skip. TODO
#                tmpm1 = re.search(r'# RANCID-CONTENT-TYPE: juniper', whole_config_str)
#                if tmpm1:
#                    break
#                m_vendor = re.search(r'RANCID-CONTENT-TYPE: (.*)\n', whole_config_str)
#                if m_vendor:
#                    vendor_name_str = m_vendor.group(1)
#                    val_lst[vlst_mod.V_VENDOR] = vendor_name_str
#                val_lst = inspect_config(whole_config_str, val_lst, vendor_name_str)
#                hash_dict.setdefault(key_tuple, val_lst)
#                glb_hash_dict[key_tuple] = val_lst
#                glb_head_dict[fname_str] = head_version_int
#                #glb_hash_dict.setdefault(key_tuple, val_lst)
#                curr_config_str = whole_config_str
#            else:
#                curr_config_str = get_change(txt_for_ver_str, curr_config_str,val_lst, vendor_name_str)
#                val_lst = inspect_config(curr_config_str,val_lst, vendor_name_str)
#                hash_dict.setdefault(key_tuple, val_lst)
#                glb_hash_dict[key_tuple] = val_lst
#                #glb_hash_dict.setdefault(key_tuple, val_lst)
#                if version_str=='1.0':
#                    pass
#                    #print 'last version'
#  #              print "pre version"
#                    
#    # end of while
#    
#    #items = hash_dict.items()
#    #keys = hash_dict.keys()
#    #print sorted(keys, key=lambda k: k[2])
#    #keys.sort()
#    #print items
#    #print keys
#    
#    #print hash_dict

    return fname_str
### end of function ###




#### Extract function ####
def extract_lines(arg_file, file_name):
    vendor_name_str=''
    val_lst = []
    #i=0
    for i in range(vlst_mod.LIST_SIZE):
        val_lst.append(0)
    val_lst[vlst_mod.V_DTYPE] = 3
    val_lst[vlst_mod.V_VENDOR] = ' '

    #val_lst = vlst_mod.create(tmp_lst)

    content_str = arg_file.read()
    tmp_str = content_str

    # get filename, without the whole path.
    f_idx = file_name.rfind('/') + 1
    fname_str = file_name[f_idx:]

    # search for head version
    match = re.search(r'head\t(\d*)\.(\d*);', content_str)
    if match:
        major_ver_str = match.group(1)
        minor_ver_str = match.group(2)
        head_version_str =  major_ver_str + "." + minor_ver_str
        version_str = head_version_str
        version_int = int(major_ver_str) * MAJOR_VER_SIZE + int(minor_ver_str)
        head_version_int = version_int

    # Start extracting text from RCS file
    while version_int >= (1*MAJOR_VER_SIZE+1):
        v_name = val_lst[vlst_mod.V_VENDOR]
        v_type = val_lst[vlst_mod.V_DTYPE]
        val_lst=[]
        i=0
        for i in range(vlst_mod.LIST_SIZE):
            val_lst.append(0)
        val_lst[vlst_mod.V_VENDOR] = v_name
        val_lst[vlst_mod.V_DTYPE] = v_type

        # Search for date
        search_str = version_str + '\nlog\n'
        match = re.search(search_str, tmp_str)
        if match:
            start_index = match.end()
            tmp_str = tmp_str[start_index:]
        match2 = re.search('@.*\n', tmp_str)
        if match2: 
            date_str =  match2.group(0).strip('\n')
            new_date_int = get_date(date_str)
  
        val_lst[vlst_mod.V_DATE] = new_date_int

        # Make tuple - key for dictionary
        key_tuple =  fname_str, version_int
        #key_tuple =  fname_str, new_date_int, version_int
        
        # search for text
        search_str = '@\ntext\n@'
        match3 = re.search(search_str, tmp_str)

        if match3:
            start_text_int = match3.end()
            tmp_str = tmp_str[start_text_int:]
    
            # if head version, it is the whole configuration.
            # else, it is changelogs
            if version_str==head_version_str:
                is_head_ver_int = 1
            else:
                is_head_ver_int = 0
    
            tmp_ver_int = int(minor_ver_str)-1
            minor_ver_str = str(tmp_ver_int)
            version_str = major_ver_str + "." + str(tmp_ver_int)
            version_int = int(major_ver_str) * MAJOR_VER_SIZE + int(minor_ver_str)
    
            # search for text end.
            search_str = version_str + '\nlog\n'
            match4 = re.search(search_str,tmp_str)
            if match4:
                end_text_int = match4.start()
                txt_for_ver_str = tmp_str[:end_text_int]
            else: 
                txt_for_ver_str = tmp_str
            if is_head_ver_int==1:
                whole_config_str = txt_for_ver_str
                # if juniper, for now, just skip. TODO
                tmpm1 = re.search(r'# RANCID-CONTENT-TYPE: juniper', whole_config_str)
                if tmpm1:
                    break
                m_vendor = re.search(r'RANCID-CONTENT-TYPE: (.*)\n', whole_config_str)
                if m_vendor:
                    vendor_name_str = m_vendor.group(1)
                    val_lst[vlst_mod.V_VENDOR] = vendor_name_str
                val_lst = inspect_config(whole_config_str, val_lst, vendor_name_str)
                hash_dict.setdefault(key_tuple, val_lst)
                glb_hash_dict[key_tuple] = val_lst
                glb_head_dict[fname_str] = head_version_int
                #glb_hash_dict.setdefault(key_tuple, val_lst)
                curr_config_str = whole_config_str
            else:
                curr_config_str = get_change(txt_for_ver_str, curr_config_str,val_lst, vendor_name_str)
                val_lst = inspect_config(curr_config_str,val_lst, vendor_name_str)
                hash_dict.setdefault(key_tuple, val_lst)
                glb_hash_dict[key_tuple] = val_lst
                #glb_hash_dict.setdefault(key_tuple, val_lst)
                if version_str=='1.0':
                    pass
                    #print 'last version'
  #              print "pre version"
                    
    # end of while
    
    #items = hash_dict.items()
    #keys = hash_dict.keys()
    #print sorted(keys, key=lambda k: k[2])
    #keys.sort()
    #print items
    #print keys
    
    #print hash_dict

    return fname_str
### end of function ###

#### main function ####
def main():
    args = sys.argv[1:]
    if not args:
        print '\n##############################################################'
        print 'usage: python cvs_alz_py <input dir> <device type>'
        print '###############################################################\n'
        sys.exit(1)

    # make directory of <output_dir>
    #os.mkdir(args[1])

    os.chdir(args[0])
    file_lst = os.listdir(args[0])
    for line in file_lst:
        f1 = open(line, 'rU')
        fname_str = extract_lines_2(f1,line, args[1])
        f1.close()
    #end of loop
 
    #print glb_hash_dict

    # put global hash dictionary into database
    try:
        conn = mdb.connect('143.215.131.215','hyojoon','dp4sqljoon','netconfig_joon')
        cursor = conn.cursor()

        # Do the thing.
        for key in glb_hash_dict.iterkeys():
            value_lst = glb_hash_dict.get(key)

            tmp_str = 'INSERT INTO rcs_tbl_3 VALUES('+'\''+key[0]+'\''+','+str(key[1])+','+str(key[2])+','+str(value_lst[vlst_mod.V_DTYPE])+','+'\''+value_lst[vlst_mod.V_VENDOR]+'\''+','+str(value_lst[vlst_mod.N_DEV_MGT])+','+str(value_lst[vlst_mod.N_L1])+','+str(value_lst[vlst_mod.N_L2])+','+str(value_lst[vlst_mod.N_VLAN])+','+str(value_lst[vlst_mod.N_L3_S])+','+str(value_lst[vlst_mod.N_L3_RTR])+','+str(value_lst[vlst_mod.N_ACL])+','+str(value_lst[vlst_mod.N_SEC])+','+str(value_lst[vlst_mod.N_C_FLT])+','+str(value_lst[vlst_mod.N_QOS])+','+str(value_lst[vlst_mod.N_ETC])+','+str(value_lst[vlst_mod.N_GBG])+','+str(value_lst[vlst_mod.N_TOTAL])+','+str(value_lst[vlst_mod.ADD_DEV_MGT])+','+str(value_lst[vlst_mod.ADD_L1])+','+str(value_lst[vlst_mod.ADD_L2])+','+str(value_lst[vlst_mod.ADD_VLAN])+','+str(value_lst[vlst_mod.ADD_L3_S])+','+str(value_lst[vlst_mod.ADD_L3_RTR])+','+str(value_lst[vlst_mod.ADD_ACL])+','+str(value_lst[vlst_mod.ADD_SEC])+','+str(value_lst[vlst_mod.ADD_C_FLT])+','+str(value_lst[vlst_mod.ADD_QOS])+','+str(value_lst[vlst_mod.ADD_ETC])+','+str(value_lst[vlst_mod.ADD_GBG])+','+str(value_lst[vlst_mod.ADD_TOTAL])+','+str(value_lst[vlst_mod.DEL_DEV_MGT])+','+str(value_lst[vlst_mod.DEL_L1])+','+str(value_lst[vlst_mod.DEL_L2])+','+str(value_lst[vlst_mod.DEL_VLAN])+','+str(value_lst[vlst_mod.DEL_L3_S])+','+str(value_lst[vlst_mod.DEL_L3_RTR])+','+str(value_lst[vlst_mod.DEL_ACL])+','+str(value_lst[vlst_mod.DEL_SEC])+','+str(value_lst[vlst_mod.DEL_C_FLT])+','+str(value_lst[vlst_mod.DEL_QOS])+','+str(value_lst[vlst_mod.DEL_ETC])+','+str(value_lst[vlst_mod.DEL_GBG])+','+str(value_lst[vlst_mod.DEL_TOTAL])+','+str(value_lst[vlst_mod.MOD_DEV_MGT])+','+str(value_lst[vlst_mod.MOD_L1])+','+str(value_lst[vlst_mod.MOD_L2])+','+str(value_lst[vlst_mod.MOD_VLAN])+','+str(value_lst[vlst_mod.MOD_L3_S])+','+str(value_lst[vlst_mod.MOD_L3_RTR])+','+str(value_lst[vlst_mod.MOD_ACL])+','+str(value_lst[vlst_mod.MOD_SEC])+','+str(value_lst[vlst_mod.MOD_C_FLT])+','+str(value_lst[vlst_mod.MOD_QOS])+','+str(value_lst[vlst_mod.MOD_ETC])+','+str(value_lst[vlst_mod.MOD_GBG])+','+str(value_lst[vlst_mod.MOD_TOTAL])+',\''+value_lst[vlst_mod.STATE]+'\')'
            #tmp_str = 'INSERT INTO rcs_tbl VALUES('+'\''+key[0]+'\''+','+str(key[1])+','+str(value_lst[vlst_mod.V_DATE])+','+str(value_lst[vlst_mod.V_DTYPE])+','+'\''+value_lst[vlst_mod.V_VENDOR]+'\''+','+str(value_lst[vlst_mod.N_DEV_MGT])+','+str(value_lst[vlst_mod.N_ARP])+','+str(value_lst[vlst_mod.N_VLAN])+','+str(value_lst[vlst_mod.N_IP_SET])+','+str(value_lst[vlst_mod.N_RTR])+','+str(value_lst[vlst_mod.N_ACL])+','+str(value_lst[vlst_mod.N_OBJ_DEF])+','+str(value_lst[vlst_mod.N_SELF_SEC])+','+str(value_lst[vlst_mod.N_LB])+','+str(value_lst[vlst_mod.N_RT])+','+str(value_lst[vlst_mod.N_ETC])+','+str(value_lst[vlst_mod.N_GBG])+','+str(value_lst[vlst_mod.N_TOTAL])+','+str(value_lst[vlst_mod.CH_DEV_MGT])+','+str(value_lst[vlst_mod.CH_ARP])+','+str(value_lst[vlst_mod.CH_VLAN])+','+str(value_lst[vlst_mod.CH_IP_SET])+','+str(value_lst[vlst_mod.CH_RTR])+','+str(value_lst[vlst_mod.CH_ACL])+','+str(value_lst[vlst_mod.CH_OBJ_DEF])+','+str(value_lst[vlst_mod.CH_SELF_SEC])+','+str(value_lst[vlst_mod.CH_LB])+','+str(value_lst[vlst_mod.CH_RT])+','+str(value_lst[vlst_mod.CH_ETC])+','+str(value_lst[vlst_mod.CH_GBG])+','+str(value_lst[vlst_mod.CH_TOTAL])+')'
 
            #print tmp_str
            #print key
            #print value_lst       
            cursor.execute(tmp_str)
    
        # commit
        conn.commit()

        for key in glb_head_dict.iterkeys():
            value_lst = []
            value_lst = glb_head_dict.get(key)
            query_str = 'INSERT into dev_tbl VALUES(\''+key+'\','+str(value_lst)+')'
            #print query_str
            cursor.execute(query_str)
 
        # commit
        conn.commit()

        # close
        cursor.close()
        conn.close()
    except mdb.Error, e:
        print "Error %d: %s" % (e.args[0],e.args[1])
        sys.exit(1)
### end of function ###

### START ###
if __name__ == '__main__':
    main()
### end of function ###
