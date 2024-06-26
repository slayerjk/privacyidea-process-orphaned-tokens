#!/usr/bin/env python3

import logging
from datetime import datetime
from os import mkdir, path, remove
from pathlib import Path
from socket import gethostname, gethostbyname
from subprocess import run, call
from shutil import which
from tempfile import TemporaryFile
from json import loads, load, dumps
from re import findall
from mysql.connector import connect
from ldap3 import Server, Connection
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups as ad_add_to_group
from smtplib import SMTP
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

#######################################
# PROGRAM DATE(EDIT THIS SECTION)

# DEFINE HOW MANY FILES TO KEEP(MOST RECENT)
logs_to_keep = 30

# CURRENT HOST DATA
hostname = gethostname()
host_ip = gethostbyname(gethostname())

# SCRIPT DATA FILE PATH

# DEFINING CREDS & ETC DATA
work_dir = path.dirname(__file__)
script_data = f'{work_dir}/script-data.json'

if not path.isfile(script_data):
    logging.error(f'{script_data} DOES NOT EXIST, exiting')
    exit()

with open(script_data, 'r', encoding='utf-8') as file:
    data = load(file)
    # PIDEA DB DATA
    pidea_db = data['pidea']['pidea_db']
    pidea_db_host = data['pidea']['pidea_db_host']
    db_user = data['pidea']['db_user']
    db_pass = data['pidea']['db_pass']
    # LDAP DATA
    dc_host = data['ldap']['dc_host']
    domain_root = data['ldap']['domain_root']
    ldap_port = data['ldap']['ldap_port']
    ad_bind_user = data['ldap']['ad_bind_user']
    ad_bind_user_pass = data['ldap']['ad_bind_user_pass']
    ad_remote_access_group = data['ldap']['ad_remote_access_group']
    # SMTP DATA
    send_mail_option = data['smtp']['send_mail_option']
    smtp_server = data['smtp']['smtp_server']
    smtp_port = data['smtp']['smtp_port']
    from_addr = data['smtp']['from_addr']
    to_addr_list = data['smtp']['to_addr_list']
    to_addr_admin_only = data['smtp']['to_addr_admin_only']


################################
# NO NEED TO EDIT FURTHER!
################################

#######################
# LOGGING SECTION
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

# ADDITIONAL DATA
token_user_dict = dict()
pidea_serial_pattern = r'^(TOTP.{8})\s\(totp\)'
pidea_janitor_path = which('privacyidea-token-janitor')
tokens_orphaned = []
tokens_user_not_found = []
tokens_to_del = []
actual_users_dn = []
user_not_found_in_cur_domain = dict()

#####################
# FUNCTIONS


# FILES ROTATION
def files_rotate(path_to_rotate, num_of_files_to_keep):
    count_files_to_keep = 1
    basepath = sorted(Path(path_to_rotate).iterdir(), key=path.getctime, reverse=True)
    for entry in basepath:
        if count_files_to_keep > num_of_files_to_keep:
            remove(entry)
            logging.info(f'removed file was: {entry}')
        count_files_to_keep += 1


# ESTIMATED TIME
def count_script_job_time():
    try:
        logging.info('START: log rotation...')
        files_rotate(logs_dir, logs_to_keep)
        logging.info('DONE: log rotation\n')    
    except Exception as error:
        logging.exception(f'ERROR: FAILURE to rotate logs\n{error}')
    
    end_date = datetime.now()
    logging.info('Estimated time is: ' + str(end_date - today))
    logging.info('######################\n')
    exit()


# EMAIL REPORT
def send_mail(mail_type):
    message = MIMEMultipart()
    rcpt_to = None
    body = None
    if send_mail_option == 'yes':
        if mail_type == 'token-with-no-users':
            message["Subject"] = f'PrivacyIdea: Orphaned token(s) with NO mapped user found in DB({today})'
            message["To"] = ', '.join(to_addr_list)
            rcpt_to = to_addr_list
            msg_content = dumps(tokens_user_not_found, indent=4)
            message.attach(MIMEText(msg_content, 'plain'))
            body = message.as_string()
            logging.info('START: sending email about tokens with no users')
        elif mail_type == 'user-not-found-current-domain':
            message["Subject"] = f'PrivacyIdea: User of orphaned token(s) NOT found in current domain({today})'
            message["To"] = ', '.join(to_addr_list)
            rcpt_to = to_addr_list
            msg_content = dumps(user_not_found_in_cur_domain, indent=4)
            message.attach(MIMEText(msg_content, 'plain'))
            body = message.as_string()
            logging.info('START: sending email about users not found in the current domain')
        elif mail_type == 'active-users':
            message["Subject"] = f'PrivacyIdea: Active domain user of orphaned token(s) found({today})'
            message["To"] = ', '.join(to_addr_list)
            rcpt_to = to_addr_list
            active_users_temp_file.seek(0)
            input_file = active_users_temp_file.read()
            message.attach(MIMEText(input_file, "plain"))
            body = message.as_string()
            logging.info('START: sending email about active users in the current domain')            
        elif mail_type == 'script-error':
            message["Subject"] = f'PrivacyIdea: ERROR Processing orphaned tokens script({today})'
            message["To"] = ', '.join(to_addr_admin_only)
            rcpt_to = to_addr_admin_only
            with open(app_log_name, 'r') as log:
                input_file = log.read()
            message.attach(MIMEText(input_file, "plain"))
            body = message.as_string()
            logging.info('START: sending script error report')

        try:
            with SMTP(smtp_server, smtp_port) as send_email:
                send_email.ehlo()
                send_email.sendmail(from_addr, rcpt_to, body)
                send_email.quit()
                logging.info('DONE: sending email report\n')
        except Exception as error:
            logging.exception(f'FAILED: sending email report, moving on...\n{error}')
        if type == 'script-error':
            count_script_job_time()                

    else:
        if type == 'script-error':
            logging.info('Email report was not set, skipping')
            count_script_job_time()
        else:
            logging.info('Email report was not set, skipping')
            

#####################
# MAIN WORKFLOW

# CHECK SERVICE STATUS
'''
No need to run script if <critical service> isn't active
'''
# CHECK ACTIVE NODE
critical_service_name = 'freeradius'
if call(['systemctl', 'is-active', 'freeradius']) != 0:
    logging.warning('Freeradius is not active on this node, finishing job...')
    count_script_job_time()
else:
    logging.info('Freeradius is UP, moving on...\n')
    logging.info('##############################')


# SEARCH ORPHANED TOKENS(SERIALS)
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


# SEARCH TOKEN'S USERS IN PI DB
logging.info('START: searching for USERS of orphaned tokens\n')
logging.info('START: establishing MYSQL connection')

try:
    with connect(
        host=pidea_db_host,
        user=db_user,
        password=db_pass,
        database=pidea_db
    ) as connection:
        logging.info('DONE: MYSQL connection established\n')
        logging.info('START: getting MYSQL query results')
        for token in tokens_orphaned:
            select_test_query = f"SELECT user FROM pidea_audit WHERE serial = \
            '{token}' AND user != '' AND user IS NOT NULL"
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
                except Exception as err:
                    logging.exception(f'FAILURE: getting MYSQL query result, finishing job...\n{err}')
                    send_mail('script-error')
except Exception as err:
    logging.exception(f'FAILURE: establishing MYSQL connection\n{err}\nfinishing job...')
    send_mail('script-error')

logging.info('DONE: getting MYSQL query results\n')

# IF THERE IS/ARE TOKEN(S) WITH NO USER FOUND IN DB - SEND EMAIL
if len(tokens_user_not_found) > 0:
    logging.warning(f'Tokens with NO user found in DB: {tokens_user_not_found}\n')
    send_mail('token-with-no-users')

if len(token_user_dict) == 0:
    logging.warning(f'NO users to proceed, exiting...\n')
    count_script_job_time()
else:
    logging.info(f'Current token-user list:\n{token_user_dict}\n')

# SEARCHING ORPHANED TOKENS' USERS IN LDAP
logging.info('START: establishing LDAP binding')

ldap_server = Server(dc_host, port=ldap_port)
active_users_temp_file = TemporaryFile('w+t')
try:
    conn = Connection(ldap_server, ad_bind_user, ad_bind_user_pass, auto_bind=True)
    logging.info('DONE: establishing LDAP binding\n')
    logging.info(f'Connection details:\n{conn}\n')
    logging.info('START: searching LDAP users info\n')
    try:
        for token, user in token_user_dict.items():
            conn.search(domain_root, f'(&(objectclass=user)(sAMAccountName={user}))')
            response = loads(conn.response_to_json())
            try:
                if 'OU=Disabled_Users' in response["entries"][0]["dn"]:
                    logging.info(f'{user}({token}) is in OU=Disabled_Users:\n<<{response["entries"][0]["dn"]}>>\n')
                    tokens_to_del.append(token)
                else:
                    logging.info(f'{user}({token}) is ACTIVE:\n<<{response["entries"][0]["dn"]}>>\n')
                    active_users_temp_file.write(f'{response["entries"][0]["dn"]}\n')
                    actual_users_dn.append(response["entries"][0]["dn"])
            except IndexError as e:
                logging.warning(f'{user}({token} NOT FOUND IN THE CURRENT DOMAIN, skipping...')
                user_not_found_in_cur_domain[user] = token

        # IF THERE IS/ARE USER NOT FOUND IN CURRENT DOMAIN - SEND EMAIL
        if len(user_not_found_in_cur_domain) > 0:
            send_mail('user-not-found-current-domain')
    
    except Exception as err:
        logging.exception(f'FAILURE: searching LDAP users info{err}\nfinishing job...')
        send_mail('script-error')
except Exception as err:
    logging.exception(f'FAILURE: establishing LDAP binding{err}\nfinishing job...')
    send_mail('script-error')
logging.info('DONE: searching LDAP users info\n')

logging.info(f'TOKENS to del({len(tokens_to_del)})')
# logging.debug(tokens_to_del)
logging.info(f'ACTUAL users({len(actual_users_dn)})\n')
# logging.debug(actual_users_dn)

# DEL ORPHANED TOKENS(SERIALS)
if len(tokens_to_del) == 0:
    logging.warning('NO DISABLED USERS FOUND, skipping to ACTUAL users...\n')
else:
    process_token_to_del_coutner = 1
    succeeded_token_to_del_counter = 0
    logging.info('START: deleting ORPHANED tokens\n-----')
    for token in tokens_to_del:
        logging.info(f'NOW DELETING: {token}; {process_token_to_del_coutner}/{len(tokens_to_del)}')
        try:
            run([pidea_janitor_path, 'find', '--serial', token, '--action', 'delete'],
                capture_output=True, text=True).stdout
            process_token_to_del_coutner += 1
            succeeded_token_to_del_counter += 1
            logging.info('-----')
        except Exception as e:
            logging.exception(f'FAILURE: deleting {token}\n{e}\nskipping...')
            process_token_to_del_coutner += 1
    logging.info('DONE: deleting ORPHANED tokens\n')
    logging.info(f'Succedded: {succeeded_token_to_del_counter}/{len(tokens_to_del)}\n')

# ADD ACTUAL USERS TO REMOTE GROUP IN AD
user_from_dn_pattern = r'^CN=(\w+).*'
conn = None
succeeded_users_counter = None

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
            if ad_add_to_group(conn, dn, ad_remote_access_group):
                process_users_counter += 1
                succeeded_users_counter += 1
        except Exception as e:
            logging.exception(f'FAILURE: adding actual user to remote group, skipping user\n{e}')
            process_users_counter += 1

logging.info('DONE: adding actual users to remote group\n')
send_mail('active-users')
logging.info(f'Succedded: {succeeded_users_counter}/{len(actual_users_dn)}\n')

# FINISH
logging.info('#########################')
logging.info('DONE: Script job done!\n') 
count_script_job_time()
