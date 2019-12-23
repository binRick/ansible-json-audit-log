# (C) 2019, Sami Korhonen, <skorhone@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
    callback: json_audit
    type: notification
    short_description: write playbook output to json formatted log file
    version_added: historical
    description:
      - This callback writes playbook output to a file `/var/log/ansible/audit.log` directory
    requirements:
     - Whitelist in configuration
     - A writeable /var/log/ansible/audit.log by the user executing Ansible on the controller
'''

import os
import pwd
import json
import uuid
from datetime import datetime

from ansible.module_utils._text import to_bytes
from ansible.plugins.callback import CallbackBase
from ansible.parsing.ajson import AnsibleJSONEncoder

# NOTE: in Ansible 1.2 or later general logging is available without
# this plugin, just set ANSIBLE_LOG_PATH as an environment variable
# or log_path in the DEFAULTS section of your ansible configuration
# file.  This callback is an example of per hosts logging for those
# that want it.

class CallbackModule(CallbackBase):
    """
    logs playbook results in /var/log/ansible/audit.log
    """
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'notification'
    CALLBACK_NAME = 'log_audit'
    CALLBACK_NEEDS_WHITELIST = True

    def __init__(self):
        super(CallbackModule, self).__init__()

        ANSIBLE_JSON_LOG_PATH = os.environ.get('ANSIBLE_JSON_LOG_PATH', '/var/log/ansible/audit.log')

#        if not os.path.exists(os.path.dirname(ANSIBLE_JSON_LOG_PATH))
#            os.makedirs(os.path.dirname(ANSIBLE_JSON_LOG_PATH))

        self.user = self.get_username()
        self.log_path = ANSIBLE_JSON_LOG_PATH
        self.session = str(uuid.uuid1())
        self.errors = 0
        self.start_time = datetime.utcnow()
        self.environment = None
        self.playbook = None
        self.start_logged = False

    def get_username(self):
        if ('JENKINS_USER' in os.environ):
            return os.environ['JENKINS_USER']
        return pwd.getpwuid(os.getuid())[0]

    def log(self, event):
        msg = to_bytes(json.dumps(event, cls=AnsibleJSONEncoder) + "\n")
        with open(self.log_path, "ab") as fd:
            fd.write(msg)

    def v2_playbook_on_play_start(self, play):
        self.play = play
    
        if 'ANSIBLE_ENVIRONMENT_NAME' in os.environ.keys():
            self.environment = os.environ['ANSIBLE_ENVIRONMENT_NAME']
        else:
            self.environment = list(play.get_variable_manager().get_vars()['hostvars'].values())[0]['environment_name']

        if not self.start_logged:
          event = {
              'event_type': "ansible_start",
              'userid': self.user,
              'session': self.session,
              'status': "OK",
              'ansible_type': "start",
              'ansible_playbook': self.playbook,
              'ansible_environment': self.environment
          }
        self.log(event)

    def v2_playbook_on_start(self, playbook):
        path, filename = os.path.split(os.path.join(playbook._basedir, playbook._file_name))
        self.playbook = os.path.join(os.path.split(path)[1], filename)

    def v2_playbook_on_stats(self, stats):
        end_time = datetime.utcnow()
        runtime = end_time - self.start_time
        #summarize_stat = {}
        #for host in stats.processed.keys():
        #    summarize_stat[host] = stats.summarize(host)

        if self.errors == 0:
            status = "OK"
        else:
            status = "FAILED"

        event = {
            'event_type': "ansible_stats",
            'userid': self.user,
            'session': self.session,
            'status': status,
            'ansible_type': "finish",
            'ansible_playbook': self.playbook,
            'ansible_playbook_duration': runtime.total_seconds(),
            'ansible_environment': self.environment
            #'ansible_playbook_stats': summarize_stat
        }
        self.log(event)

    def v2_runner_on_ok(self, result, **kwargs):
        event = {
            'event_type': "ansible_ok",
            'userid': self.user,
            'session': self.session,
            'status': "OK",
            'ansible_type': "task",
            'ansible_playbook': self.playbook,
            'ansible_host': result._host.name,
            'ansible_task': result._task.name,
            'ansible_changed': result._result['changed'],
            'ansible_environment': self.environment
            #'ansible_task_result': self._dump_results(result._result)
        }
        self.log(event)

    def v2_runner_on_skipped(self, result, **kwargs):
        event = {
            'event_type': "ansible_skipped",
            'userid': self.user,
            'session': self.session,
            'status': "SKIPPED",
            'ansible_type': "task",
            'ansible_playbook': self.playbook,
            'ansible_task': result._task.name,
            'ansible_host': result._host.name,
            'ansible_environment': self.environment
        }
        self.log(event)

    def v2_playbook_on_import_for_host(self, result, imported_file):
        event = {
            'event_type': "ansible_import",
            'userid': self.user,
            'session': self.session,
            'status': "IMPORTED",
            'ansible_type': "import",
            'ansible_playbook': self.playbook,
            'ansible_host': result._host.name,
            'ansible_imported_file': imported_file,
            'ansible_environment': self.environment
        }
        self.log(event)

    def v2_playbook_on_not_import_for_host(self, result, missing_file):
        event = {
            'event_type': "ansible_import",
            'userid': self.user,
            'session': self.session,
            'status': "NOT IMPORTED",
            'ansible_type': "import",
            'ansible_playbook': self.playbook,
            'ansible_host': result._host.name,
            'ansible_missing_file': missing_file,
            'ansible_environment': self.environment
        }
        self.log(event)

    def v2_runner_on_failed(self, result, **kwargs):
        event = {
            'event_type': "ansible_failed",
            'userid': self.user,
            'session': self.session,
            'status': "FAILED",
            'ansible_type': "task",
            'ansible_playbook': self.playbook,
            'ansible_host': result._host.name,
            'ansible_task': result._task.name,
            'ansible_environment': self.environment
            #'ansible_task_result': self._dump_results(result._result)
        }
        self.errors += 1
        self.log(event)

    def v2_runner_on_unreachable(self, result, **kwargs):
        event = {
            'event_type': "ansible_unreachable",
            'userid': self.user,
            'session': self.session,
            'status': "UNREACHABLE",
            'ansible_type': "task",
            'ansible_playbook': self.playbook,
            'ansible_host': result._host.name,
            'ansible_task': result._task.name,
            'ansible_environment': self.environment
            #'ansible_task_result': self._dump_results(result._result)
        }
        self.errors += 1
        self.log(event)

    def v2_runner_on_async_failed(self, result, **kwargs):
        event = {
            'event_type': "ansible_async",
            'userid': self.user,
            'session': self.session,
            'status': "FAILED",
            'ansible_type': "task",
            'ansible_playbook': self.playbook,
            'ansible_host': result._host.name,
            'ansible_task': result._task.name,
            'ansible_environment': self.environment
            #'ansible_task_result': self._dump_results(result._result)
        }
        self.errors += 1
        self.log(event)
