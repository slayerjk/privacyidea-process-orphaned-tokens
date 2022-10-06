# privacyidea-process-orphaned-tokens
Script is automatization for processing orphaned tokens(del for disabled user; add to ad group for active users) based on AD users.

**Workflow:**
-search for orphaned tokens using 'privacyidea-token-janitor';
-search for users of orphaned tokens using 'pidea_audit' of 'pi' db;
-search for AD(LDAP) users who is in 'OU=Disabled_Users' and who is not;
-delete orphaned tokens based on users in 'OU=Disabled_Users' using 'privacyidea-token-janitor';
-add users which are not disabled(actual) to remote access group of PrivacyIdea.


**Requirements:**
Script has written using 'Python 3.10.4'.

Work confirmed on 'Python 3.8.10'.

Creds/etc data file, named '**script-data**' stored in script's work dir and consist of five strings(newline for each):
- pidea db username
- pidea db user pass
- full ad bind user, like 'cn=bind_user,ou=users,…'
- ad bind user's password
- full dn of remote access group of PI

Looks like above:
```
download
db_user
db_user_pass
CN=binddn,OU=Users,OU=Enterprise groups,DC=example,DC=com
binddn_pass
CN=remote_access,OU=Remote_Access,DC=example,DC=com
```

**Used modules:**
```
import logging
from datetime import datetime, date
from os import mkdir, path, remove
from pathlib import Path
from socket import gethostname, gethostbyname
from subprocess import run
from shutil import which
from tempfile import TemporaryFile
from json import loads
from re import findall
from mysql.connector import connect, Error
from ldap3 import Server, Connection
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups as ADAddToGroup
```
