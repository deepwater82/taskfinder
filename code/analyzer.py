######################################################
# Georgia Institute of Technology
# author: Hyojoon Kim
# date: 2011.12.8
#
# analyzer.py
#  - Network configuration bulk change inspection.
#
######################################################

import sys
import re
import datetime
import time
import os
import shutil


## Global variables 
MAJOR_VER_SIZE = 10000


#### classify vendor  ####
def classify_vendor(vendor_name_str):
    return 0
#### end of method ####

#### Get changelog function ####
def get_change(txt_str, whole_str, output_file):

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
    now_lstlines = now_conf_str.splitlines()
    tmp_lstlines = tmp_conf_str.splitlines()
    num_entry_int = len(lstlines)
    content_str = ''
    
    # open change log file
    chglog_file = open(output_file,'w+')

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
                add_cmd_str = now_lstlines.pop(int(match1.group(1))-1+adapt_int)
                chglog_file.write('add ' + add_cmd_str+'\n')
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
                    del_cmd_str = lstlines[i+j+1]
                    chglog_file.write('del ' + del_cmd_str+'\n')
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
                   adapt_int = 0
#                   for k in now_lstlines:
#                       if k=='':
#                           now_lstlines.remove(k)
#                           print 'yaya'
               break
    # end of while

    curr_conf_str = ''
    for i in now_lstlines:
        curr_conf_str = curr_conf_str+i+'\n'

    chglog_file.close()

    return curr_conf_str
#### end of function ####


#### process device ####
def process_device(dev_file, fname_str,output_dir):
    dev_whole_dct = {}
    dev_change_dct = {}
    state_dict = {}
    key_lst = []
    val_lst = []
    prev_val_lst = []
    version_int = 0
    vendor_name_str=''
    
#    for i in range(vlst_mod.LIST_SIZE):
#        val_lst.append(0)
#    val_lst[vlst_mod.V_DTYPE] = int(device_type)
#    val_lst[vlst_mod.V_VENDOR] = ' '

    content_str = dev_file.read()
    tmp_str = content_str

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
        print fname_str
        sys.exit(1)

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
            sys.exit(1)
    # end of while loop
    
    # recover version string and int
    version_str = head_version_str
    version_int = head_version_int

    key_lst_idx = 0

    # Let's do the main job
    while version_int >= (1*MAJOR_VER_SIZE+1):
        # initialize
        #v_name = val_lst[vlst_mod.V_VENDOR]
        #v_type = val_lst[vlst_mod.V_DTYPE]
        #val_lst=[]
        #for i in range(vlst_mod.LIST_SIZE):
        #    val_lst.append(0)

        # preserve some data
        #val_lst[vlst_mod.V_VENDOR] = v_name
        #val_lst[vlst_mod.V_DTYPE] = v_type

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
                        classify_vendor(vendor_name_str)
#val_lst[vlst_mod.V_VENDOR] = vendor_name_str
                else:
                    break
                
                # save config
                key_tuple = key_lst[key_lst_idx]
                out_file_name_con_str = str(key_tuple[0]) + '_' + str(key_tuple[1]) + '_'+ str(key_tuple[2]) + '_config' 
                #out_file_name_chg_str = str(key_tuple[0]) + '_' + str(key_tuple[1]) + '_'+ str(key_tuple[2]) + '_change' 
                out_file = open(output_dir+out_file_name_con_str, 'w+')
                out_file.write(whole_config_str)
                out_file.close()
                #out_file = open(output_dir+out_file_name_chg_str, 'w+')
                #out_file.write(' ')
                #out_file.close()
                
                # inspect config string
                #val_lst = inspect_config(whole_config_str, val_lst, vendor_name_str)
                # put to global hash dictionary
                #key_tuple = key_lst[key_lst_idx]
                #val_lst[vlst_mod.STATE] = state_dict[key_tuple]
                #glb_hash_dict[key_tuple] = val_lst
                # put to global head dictionary
                #glb_head_dict[fname_str] = head_version_int
                #glb_hash_dict.setdefault(key_tuple, val_lst)
                #hash_dict.setdefault(key_tuple, val_lst)
                # save current configuration string, for later usage by changelog
                prev_config_str = whole_config_str
                #prev_val_lst = val_lst
                #prev_key_tuple = key_tuple

            # else, go through changelog, and produce text
            else:
                key_tuple = key_lst[key_lst_idx]
                key_tuple_chg = key_lst[key_lst_idx-1]
                out_file_name_con_str = str(key_tuple[0]) + '_' + str(key_tuple[1]) + '_'+ str(key_tuple[2]) + '_config' 
                out_file_name_chg_str = str(key_tuple_chg[0]) + '_' + str(key_tuple_chg[1]) + '_'+ str(key_tuple_chg[2]) + '_change' 

                curr_config_str = get_change(txt_for_ver_str, prev_config_str,output_dir+out_file_name_chg_str)
                out_file = open(output_dir+out_file_name_con_str, 'w+')
                out_file.write(curr_config_str)
                out_file.close()

                # if first commit, the changelog is the config itself, added
                if key_lst_idx == len(key_lst)-1:
                    out_file_name_chg_str = str(key_tuple[0]) + '_' + str(key_tuple[1]) + '_'+ str(key_tuple[2]) + '_change' 
                    out_file = open(output_dir+out_file_name_chg_str, 'w+')
                    out_file.write('FIRST COMMIT!\n\n' + curr_config_str)
                    out_file.close()
                    
                # Get context diff
#                prev_config_lst = prev_config_str.splitlines()
#                curr_config_lst = curr_config_str.splitlines()
#                context_diff_str = difflib.context_diff(curr_config_lst, prev_config_lst)
#                get_diff(context_diff_str, prev_val_lst, vendor_name_str)
#                # update previous dict entry
#                tmp_dict.clear()
#                tmp_dict[prev_key_tuple] = prev_val_lst
#                glb_hash_dict.update(tmp_dict)
#
#                val_lst = inspect_config(curr_config_str,val_lst, vendor_name_str)
#                #hash_dict.setdefault(key_tuple, val_lst)
#                key_tuple = key_lst[key_lst_idx]
#                val_lst[vlst_mod.STATE] = state_dict[key_tuple]
#                glb_hash_dict[key_tuple] = val_lst
                
#                # preserve    
#                prev_val_lst=[]
#                for j in range(vlst_mod.LIST_SIZE):
#                    prev_val_lst.append(0)
#                prev_val_lst = val_lst
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

    return 0
### end of method ###

#### main function ####
def main():
    args = sys.argv[1:]
    if len(args)!=2:
        print '\n###############################################################'
        print 'usage: python analyzer.py <input directory> <output directory>\n'
        print '       - directory paths should be full paths.\n'
        print '###############################################################\n'
        sys.exit(1)

    # Check if output dir exists.
    if(os.access(args[1], os.F_OK)):
        answer_str = raw_input('output directory exists. Remove? (y/n):')
        if answer_str=='y':
            try:
                shutil.rmtree(args[1])
            except Error, err:
                errors.extend(err.args[0])
                print 'Cannot remove. Exit.'
                sys.exit(1)
        elif answer_str=='n':
            print 'Overwrite not allowed. Exit.'
            sys.exit(1)
        else:
            print 'Wrong input. Exit.'
            sys.exit(1)
            
    # make directory for output
    os.mkdir(args[1])

    # Get the list of devices
    dev_lst = os.listdir(args[0])
 
    # do some directory sanity check, fix.
    indir_str = ''
    if not (args[0].endswith('/')):
        indir_str = '/'
    outdir_str = ''
    if not (args[1].endswith('/')):
        outdir_str = '/'

    # Start process
    for dev in dev_lst:
        if dev.startswith('.'): # if hidden file, no.
            pass
        elif dev.endswith('.xfw,v'): # if f/w extension, no.
            pass
        elif dev.endswith(',v'):
            fd = open(args[0]+indir_str+dev,'r')
            process_device(fd,dev,args[1]+outdir_str)
            fd.close()
        else: # if none, no.
            pass
    print 'done'
    return 0
### end of function ###

### START ###
if __name__ == '__main__':
    main()
### end of function ###
