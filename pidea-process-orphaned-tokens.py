#!/usr/bin/env python3

import logging
from datetime import datetime
from os import mkdir, path, remove
from pathlib import Path
from socket import gethostname, gethostbyname
from subprocess import run, call
from shutil import which
from tempfile import TemporaryFile
from json import loads
from re import findall
from mysql.connector import connect
from ldap3 import Server, Connection
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups as ADAddToGroup
import smtplib

#######################################
### PROGRAM DATE(EDIT THIS SECTION) ###

### WORKING DIR ###
work_dir = '<your-abs-path-to-script-dir>'

### DEFINE HOW MANY FILES TO KEEP(MOST RECENT) ###
logs_to_keep = 30

### CURRENT HOST DATA ###
hostname = gethostname()
host_ip = gethostbyname(gethostname())

### PIDEA DB DATA ###
pidea_db = 'pi'

### LDAP DATA ###
dc_host = '<your DC>'
domain_root = 'dc=ex,dc=com'
ldap_port = 389

### SCRIPT DATA FILE PATH ###
'''
creds file consist of four strings(newline for each):
1) pidea db username
2) pidea db user pass
3) full ad bind user, like 'cn=bind_user,ou=users,...'
4) ad bind user's password
5) full dn of remote access group of PI
'''
script_data = work_dir+'/script-data'

### SMTP DATA(WITHOUT AUTH) ###
'''
For an email alert when tokens with NO user found in DB
'''
send_mail_option = 'yes'
smtp_server = '<your-smtp-server'
from_addr = '2fa@ex.comz'
to_addr_list = ['admin@ex.com', 'user2@ex.com', 'user3@ex.com']
to_addr_admin_only = 'admin@bcc.kz'
smtp_port = 25

################################
### NO NEED TO EDIT FURTHER! ###
################################

#######################
### LOGGING SECTION ###
today = datetime.now()
logs_dir = '/var/log/pidea-process-orphaned-tokens'

if not path.isdir(logs_dir):
    mkdir(logs_dir)

app_log_name = logs_dir+'/pidea-del-orphaned-tokens_' + \
    str(today.strftime('%d-%m-%Y'))+'.log'

logging.basicConfig(filename=app_log_name, filemode='a', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%d-%b-%Y %H:%M:%S')

logging.info('----------------------------------------------')
logging.info('SCRIPT WORK STARTED: DEL PIDEA ORPHANED TOKENS')
logging.info('Script Starting Date&Time is: ' +
             str(today.strftime('%d/%m/%Y %H:%M:%S')))
logging.info(f'PIDEA NODE HOSTNAME: {hostname}')
logging.info(f'PIDEA NODE IP: {host_ip}\n')

### ADDITIONAL DATA ###
token_user_dict = dict()
pidea_serial_pattern = '^(TOTP.{8})\s\(totp\)'
pidea_janitor_path = which('privacyidea-token-janitor')
tokens_orphaned = []
tokens_user_not_found = []
tokens_to_del = []
actual_users_dn = []

#####################
##### FUNCTIONS #####

### FILES ROTATION ###
def files_rotate(path_to_rotate, num_of_files_to_keep):
    count_files_to_keep = 1
    basepath = sorted(Path(path_to_rotate).iterdir(), key=path.getctime, reverse=True)
    for entry in basepath:
        if count_files_to_keep > num_of_files_to_keep:
            remove(entry)
            logging.info(f'removed file was: {entry}')
        count_files_to_keep += 1

### ESTIMATED TIME ###
def count_script_job_time():
    try:
        logging.info('START: log rotation...')
        files_rotate(logs_dir, logs_to_keep)
        logging.info('DONE: log rotation\n')    
    except Exception as error:
        logging.exception('ERROR: FAILURE to rotate logs')
    
    end_date = datetime.now()
    logging.info('Estimated time is: ' + str(end_date - today))
    logging.info('######################\n')
    exit()

### EMAIL REPORT ###
def send_mail(type):
    if send_mail_option == 'yes':
        if type == 'token-info':
            subj = 'Tokens with NO user found in DB'
            msg = tokens_user_not_found
            logging.info('START: sending email about tokens with no users')
            try:
                with smtplib.SMTP(smtp_server, smtp_port) as send_mail:
                    send_mail.ehlo()
                    send_mail.sendmail(from_addr=from_addr, to_addrs=to_addr_list, msg=f'subject: {subj}({today})\n\n{today}:\n{msg}')
                    send_mail.quit()
                    logging.info('DONE: sending email about tokens with no users\n')
            except Exception as e:
                logging.warning('FAILED: sending Tokens with NO user found in DB, moving on...\n')
        elif type == 'script-error':
            logging.info('START: sending error report')
            subj = 'Pidea Process Orphaned Tokens Script Error Occured'
            with open(app_log_name, 'r') as log:
                msg = log.read()
            try:
                with smtplib.SMTP(smtp_server, smtp_port) as send_mail:
                    send_mail.ehlo()
                    send_mail.sendmail(from_addr=from_addr, to_addrs=to_addr_admin_only, msg=f'subject: {subj}({today})\n\n{today}:\n{msg}')
                    send_mail.quit()
                    logging.info('DONE: sending error report\n')
            except Exception as e:
                logging.warning('FAILED: sending error report, moving on...\n')
            count_script_job_time()
    else:
        if type == 'token-info':
            logging.info('Email report was not set, skipping')
        elif type == 'script-error':
            logging.info('Email report was not set, skipping')
            count_script_job_time()

#####################
### MAIN WORKFLOW ###

### CHECK SERVICE STATUS ###
'''
No need to run script if <critical service> isn't active
'''
### CHECK ACTIVE NODE ###
critical_service_name = 'freeradius'
if (call(['systemctl', 'is-active', 'freeradius']) != 0):
    logging.warning('Freeradius is not active on this node, finishing job...')
    count_script_job_time()
else:
    logging.info('Freeradius is UP, moving on...\n')
    logging.info('##############################')


### DEFINING CREDS & ETC DATA ###
with open(script_data, 'r', encoding='utf-8') as file:
    data = [i.strip() for i in file.readlines()]
    db_user = data[0]
    db_pass = data[1]
    ad_bind_user = data[2]
    ad_bind_user_pass = data[3]
    ad_remote_access_group = data[4]

### SEARCH ORPHANED TOKENS(SERIALS) ###
logging.info('START: searching ORPHANED tokens')
with TemporaryFile('w+t') as temp:
    temp.write(run([pidea_janitor_path, 'find', '--orphaned', '1'], capture_output=True, text=True).stdout)
    temp.seek(0)
    for line in temp.readlines():
        if '(totp)' in line:
            tokens_orphaned.append(findall(pidea_serial_pattern, line)[0])
logging.info('DONE: searching ORPHANED tokens\n')
if len(tokens_orphaned) == 0:
    logging.warning('NO ORPHANED TOKENS FOUND, finishing job...\n')
    count_script_job_time()

logging.info(f'Current orpaned tokens list is: {tokens_orphaned}')

### SEARCH TOKEN'S USERS IN PI DB ###
pidea_db_host = host_ip

logging.info('START: searching for USERS of orphaned tokens\n')
logging.info('START: establishing MYSQL connection')

try:
    with connect(
        host= pidea_db_host,
        user = db_user,
        password = db_pass,
        database = pidea_db
    ) as connection:
        logging.info('DONE: MYSQL connection established\n')
        logging.info('START: getting MYSQL query results')
        for token in tokens_orphaned:
            select_test_query = f"SELECT user FROM pidea_audit WHERE serial = '{token}' AND user != '' AND user IS NOT NULL"
            with connection.cursor(buffered=True) as cursor:
                try:
                    cursor.execute(select_test_query)
                    try:
                        for result in cursor.fetchone():
                            token_user_dict[token] = str(result).lower()
                    except TypeError as e:
                        logging.warning(f'Probably, there is no user for {token}, skipping...')
                        tokens_user_not_found.append(token)
                        continue
                except Exception as e:
                    logging.exception('FAILURE: getting MYSQL query result, finishing job...\n')
                    send_mail('script-error')
except Exception as e:
    logging.exception('FAILURE: establishing MYSQL connection, finishing job...')
    send_mail('script-error')

logging.info('DONE: getting MYSQL query results\n')

### IF THERE IS/ARE TOKEN(S) WITH NO USER FOUND IN DB - SEND EMAIL ###
if len(tokens_user_not_found) > 0:
    logging.warning(f'Tokens with NO user found in DB: {tokens_user_not_found}\n')
    send_mail('token-info')

if len(token_user_dict) == 0:
    logging.warning(f'NO users to proceed, exiting...\n')
    count_script_job_time()
else:
    logging.info(f'Current token-user list:\n{token_user_dict}\n')

### SEARCHING ORPHANED TOKENS' USERS IN LDAP ###
logging.info('START: establishing LDAP binding')

ldap_server = Server(dc_host, port=ldap_port)

try:
    conn = Connection(ldap_server, ad_bind_user, ad_bind_user_pass, auto_bind=True)
    logging.info('DONE: establishing LDAP binding\n')
    logging.info(f'Connection details:\n{conn}\n')
    logging.info('START: searching LDAP users info\n')
    try:
        for token, user in token_user_dict.items():
            conn.search(domain_root, f'(&(objectclass=user)(sAMAccountName={user}))')
            response = loads(conn.response_to_json())
            if 'OU=Disabled_Users' in response["entries"][0]["dn"]:
                logging.info(f'{user}({token}) is in OU=Disabled_Users:\n<<{response["entries"][0]["dn"]}>>\n')
                tokens_to_del.append(token)
            else:
                logging.info(f'{user}({token}) is ACTIVE:\n<<{response["entries"][0]["dn"]}>>\n')
                actual_users_dn.append(response["entries"][0]["dn"])
    except Exception as e:
        logging.exception('FAILURE: searching LDAP users info, finishing job...')
        send_mail('script-error')
except Exception as e:
    logging.exception('FAILURE: establishing LDAP binding, finishing job...')
    send_mail('script-error')
logging.info('DONE: searching LDAP users info\n')

logging.info(f'TOKENS to del({len(tokens_to_del)})')
#logging.debug(tokens_to_del)
logging.info(f'ACTUAL users({len(actual_users_dn)})\n')
#logging.debug(actual_users_dn)

### DEL ORPHANED TOKENS(SERIALS) ###
if len(tokens_to_del) == 0:
    logging.warning('NO DISABLED USERS FOUND, skipping to ACTUAL users...\n')
else:
    process_token_to_del_coutner = 1
    succeeded_token_to_del_counter = 0
    logging.info('START: deleting ORPHANED tokens\n-----')
    for token in tokens_to_del:
        try:
            logging.info(f'NOW DELETING: {token}; {process_token_to_del_coutner}/{len(tokens_to_del)}')
            run([pidea_janitor_path, 'find', '--serial', token, '--action', 'delete'], capture_output=True, text=True).stdout
            process_token_to_del_coutner += 1
            succeeded_token_to_del_counter += 1
            logging.info('-----')
        except Exception as e:
            logging.exception(f'FAILURE: deleting {token}, skipping...')
            process_token_to_del_coutner += 1
    logging.info('DONE: deleting ORPHANED tokens\n')
    logging.info(f'Succedded: {succeeded_token_to_del_counter}/{len(tokens_to_del)}\n')

### ADD ACTUAL USERS TO REMOTE GROUP IN AD ###
user_from_dn_pattern = '^CN=(\w+).*'
if len(actual_users_dn) == 0:
    logging.warning('NO ACTUAL USERS FOUND, finishing job...\n')
    count_script_job_time()
else:
    process_users_counter = 1
    succeeded_users_counter = 0
    logging.info('START: adding actual users to remote group\n-----')
    for dn in actual_users_dn:
        actual_user = findall(user_from_dn_pattern, dn)
        logging.info(f'Processing {actual_user}: {process_users_counter}/{len(actual_users_dn)}')
        try:
            if ADAddToGroup(conn, dn, ad_remote_access_group):
                process_users_counter += 1
                succeeded_users_counter += 1
        except Exception as e:
            logging.exception('FAILURE: adding actual user to remote group, skipping user')
            process_users_counter += 1

logging.info('DONE: adding actual users to remote group\n')
logging.info(f'Succedded: {succeeded_users_counter}/{len(actual_users_dn)}\n')

### FINISH ###
logging.info('#########################')
logging.info('DONE: Script job done!\n') 
count_script_job_time()
