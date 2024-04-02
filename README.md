# privacyidea-process-orphaned-tokens
Script is automatization for processing orphaned tokens(del for disabled user; add to ad group for active users) based on AD users.

**Workflow:**
1. search for orphaned tokens using 'privacyidea-token-janitor';
2. search for users of orphaned tokens using 'pidea_audit' of 'pi' db;
3. search for AD(LDAP) users who is in 'OU=Disabled_Users' and who is not;
4. delete orphaned tokens based on users in 'OU=Disabled_Users' using 'privacyidea-token-janitor';
5. add users which are not disabled(actual) to remote access group of PrivacyIdea.
6. email option(yes/no); send mail if found tokens with no mapped users; send mail if script error.

**Requirements:**
Script has written using 'Python 3.10.4'.

Work confirmed on 'Python 3.8.10'.

Creds/etc data file, named '**script-data.json**' stored in script's work dir.

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

Also you have to install myslq-connector-python for supported auth methods:
```
pip install mysql-connector-python
```
