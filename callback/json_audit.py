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

import os, time
import pwd
import json
import uuid
from datetime import datetime
import collections

from ansible.module_utils._text import to_bytes
from ansible.plugins.callback import CallbackBase
from ansible.parsing.ajson import AnsibleJSONEncoder

#import os, asyncio, threading, time
ANSIBLE_JSON_LOG_PATH = '/tmp/vpntech-bp-json-audit.dat'
PIPES =  [ANSIBLE_JSON_LOG_PATH]

"""
_WRITE_PIPE = True
def wp(dat):
    #print('waiting for opening pipe for writing')
    with open(ANSIBLE_JSON_LOG_PATH, 'w') as write_stream:
#        print('writing pipe opened')
#        time.sleep(.01)
#        print('writing some data')
        try:
            print(dat.decode(), file=write_stream)
        except Exception as e:
            pass
#        time.sleep(.01)
#    print('exiting write')

"""



if 'SERVER_UUID' in os.environ.keys():
    SERVER_UUID = os.environ['SERVER_UUID']
else:
    PLAY_UUID = None

if 'PLAY_UUID' in os.environ.keys():
    PLAY_UUID = os.environ['PLAY_UUID']
else:
    PLAY_UUID = None



def getTimestampMilliseconds():
    return int(time.time() * 1000)

def getTimestamp():
    return int(time.time())


def timestamp(self):
    if self.current is not None and self.current in TASK_START_TIMES.keys():
        self.tasks[self.current]['time'] = getTimestampMilliseconds() - TASK_START_TIMES[self.current]


def summarizeRoles(ROLES, TASKS):
    SUMMARY = {'roles': {}}
    for RT in ROLES.tasks:
        if not RT in SUMMARY['roles']:
            SUMMARY['roles'][RT] = {
                'total_ms': 0,
                'tasks': [],
            }
        for T in TASKS:
            if T == RT:
                SUMMARY['roles'][RT]['tasks'].append()                
    return SUMMARY        
    return ROLES

TASK_START_TIMES = {}
TASK_END_TIMES = {}


class CallbackModule(CallbackBase):
    """
    logs playbook results in /var/log/ansible/audit.log
    """
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'notification'
    CALLBACK_NAME = 'log_audit'
    CALLBACK_NEEDS_WHITELIST = True

    def __init__(self):
        self.tasks = collections.OrderedDict()
        self.roles = collections.OrderedDict()
        self.current = None
        self._PLAYBOOK_START_TS_MS = None
        super(CallbackModule, self).__init__()
        ANSIBLE_JSON_LOG_PATH = os.environ.get('ANSIBLE_JSON_LOG_PATH', '/tmp/ansible-audit.log')

#        if not os.path.exists(os.path.dirname(ANSIBLE_JSON_LOG_PATH))
#            os.makedirs(os.path.dirname(ANSIBLE_JSON_LOG_PATH))

        self.user = self.get_username()
        self.log_path = ANSIBLE_JSON_LOG_PATH
        self.session = str(uuid.uuid1())
        self.errors = 0
        self.start_time = getTimestampMilliseconds()
        self.environment = None
        self.playbook = None
        self.start_logged = False

    def mangleEventResult(self, event, result):
        if result._task.no_log:
            event['no_log'] = True
        else:
            event['no_log'] = False
        return event

    def _record_task(self, task):
        #print('rt type {} {}'.format(type(task), type(task._uuid)))
        if task._uuid not in TASK_START_TIMES.keys():
            TASK_START_TIMES[task._uuid] = getTimestampMilliseconds()
        else:
            TASK_END_TIMES[task._uuid] = getTimestampMilliseconds()
#            self.tasks[self.current]['duration_ms'] = TASK_END_TIMES[task._uuid] - TASK_START_TIMES[task._uuid]

        timestamp(self)

        # Record the start time of the current task
        self.current = task._uuid
        self.tasks[self.current] = {'start_ts_ms': TASK_START_TIMES[task._uuid], 'name': task.get_name()}
        if self.current in TASK_END_TIMES.keys():
            self.tasks[self.current]['end_ts'] = TASK_END_TIMES[self.current]

#        print(task.keys())



        if task.action:
            self.tasks[self.current]['action'] = task.action

        if task._role:
            self.tasks[self.current]['role'] = task._role._role_name
            if not task._role._role_name in self.roles:
                self.roles[task._role._role_name] = {'tasks': [], 'total_ms': 0}
            if not task._uuid in self.roles[task._role._role_name]['tasks']:
                self.roles[task._role._role_name]['tasks'].append(task._uuid)

#            print('roles: {}'.format(self.roles))


        if self._display.verbosity >= 2:
            self.tasks[self.current]['path'] = task.get_path()

    def get_username(self):
        return pwd.getpwuid(os.getuid())[0]

    def log(self, event):
        #event['ts_ms'] = getTimestampMilliseconds()
#        event['start_ms'] = TASK_START_TIMES[event['task_uuid']]
        event['play_uuid'] = PLAY_UUID
        event['server_uuid'] = SERVER_UUID
        event['pid'] = os.getpid()



        if 'event_type' in event.keys() and event['event_type'] != 'ansible_task_start':
            if 'task_uuid' in event.keys() and event['task_uuid'] in TASK_START_TIMES:
                event['end_ts_ms'] = getTimestampMilliseconds()
                event['start_ts_ms'] = TASK_START_TIMES[event['task_uuid']]
                event['duration_ms'] = event['end_ts_ms'] - event['start_ts_ms']

        msg = to_bytes(json.dumps(event, cls=AnsibleJSONEncoder) + "\n")

#        if _WRITE_PIPE:
#            wp(msg)

        with open(self.log_path, "ab") as fd:
            fd.write(msg)

    def v2_playbook_on_handler_task_start(self, task):
        self._record_task(task)

    def v2_playbook_on_task_start(self, task, is_conditional):
        self._PLAYBOOK_START_TS_MS = getTimestampMilliseconds()
        self._record_task(task)
        event = {
            'event_type': "ansible_task_start",
#            'userid': self.user,
            'session': self.session,
            'is_conditional': is_conditional,
            'ansible_playbook': self.playbook,
            'task_uuid': task._uuid,
            'start_ts_ms': getTimestampMilliseconds(),
#            'ansible_playbook_duration': runtime.total_seconds(),
            #'ansible_playbook_stats': summarize_stat
        }
        if task._role:
            event['role'] = task._role._role_name
        if task and task.name:
            event['ansible_task'] = task.name

            

        self.log(event)

    def v2_playbook_on_play_start(self, play):
        self.play = play
    

#        if 'ANSIBLE_ENVIRONMENT_NAME' in os.environ.keys():
#            self.environment = os.environ['ANSIBLE_ENVIRONMENT_NAME']
#        else:
#            self.environment = list(play.get_variable_manager().get_vars()['hostvars'].values())[0]['environment_name']


        if not self.start_logged:
          event = {
              'event_type': "ansible_start",
              'start_ts_ms':  getTimestampMilliseconds(),
#              'userid': self.user,
              'session': self.session,
              'status': "OK",
              'ansible_type': "start",
              'ansible_playbook': self.playbook,
#              'ansible_environment': self.environment
          }
        self.log(event)

    def v2_playbook_on_start(self, playbook):
        path, filename = os.path.split(os.path.join(playbook._basedir, playbook._file_name))
        self.playbook = os.path.join(os.path.split(path)[1], filename)

    def v2_playbook_on_stats(self, stats):
        end_time = getTimestampMilliseconds()
        runtime_ms = end_time - self.start_time
        #summarize_stat = {}
        #for host in tasks.processed.keys():
        #    summarize_stat[host] = tasks.summarize(host)

        if self.errors == 0:
            status = "OK"
        else:
            status = "FAILED"

        event = {
            'event_type': "ansible_stats",
#            'userid': self.user,
            'session': self.session,
            'status': status,
            'start_ts_ms':  self._PLAYBOOK_START_TS_MS,
            'ansible_type': "finish",
            'ansible_playbook': self.playbook,
            'ansible_playbook_duration_ms': runtime_ms,
            'tasks': self.tasks,
            'roles': self.roles,
#            'ansible_environment': self.environment
            #'ansible_playbook_stats': summarize_stat
        }
        self.log(event)


    def v2_runner_on_ok(self, result, **kwargs):
        event = {
            'event_type': "ansible_ok",
#            'userid': self.user,
            'session': self.session,
            'status': "OK",
            'ansible_type': "task",
            'ansible_playbook': self.playbook,
            'ansible_host': result._host.name,
            'ansible_task': result._task.name,
            'task_uuid': result._task._uuid,
            'ansible_changed': result._result['changed'],
#            'ansible_environment': self.environment,
#            'ansible_task_result': result._result,
        }
        event = self.mangleEventResult(event, result)

        if result._task._role and result._task._role._role_name:
            event['role'] = result._task._role._role_name
            if not event['role'] in self.roles.keys():
                self.roles[event['role']] = []
            if not result._task._uuid in self.roles[event['role']]['tasks']:
                self.roles[event['role']]['tasks'].append(result._task._uuid)

        self.log(event)

    def v2_runner_on_skipped(self, result, **kwargs):
        event = {
            'event_type': "ansible_skipped",
#            'userid': self.user,
            'session': self.session,
            'status': "SKIPPED",
            'ansible_type': "task",
            'ansible_playbook': self.playbook,
            'ansible_task': result._task.name,
            'ansible_host': result._host.name,
            'task_uuid': result._task._uuid,
#            'ansible_environment': self.environment
        }
        event = self.mangleEventResult(event, result)
        if result._task._role and result._task._role:
            event['role'] = result._task._role._role_name
        self.log(event)

    def v2_playbook_on_import_for_host(self, result, imported_file):
        event = {
            'event_type': "ansible_import",
#            'userid': self.user,
            'session': self.session,
            'status': "IMPORTED",
            'ansible_type': "import",
            'ansible_playbook': self.playbook,
            'ansible_host': result._host.name,
            'ansible_imported_file': imported_file,
            'task_uuid': result._task._uuid,
#            'ansible_environment': self.environment
        }
        event = self.mangleEventResult(event, result)
        self.log(event)

    def v2_playbook_on_not_import_for_host(self, result, missing_file):
        event = {
            'event_type': "ansible_import",
#            'userid': self.user,
            'session': self.session,
            'status': "NOT IMPORTED",
            'ansible_type': "import",
            'ansible_playbook': self.playbook,
            'ansible_host': result._host.name,
            'ansible_missing_file': missing_file,
            'task_uuid': result._task._uuid,
#            'ansible_environment': self.environment
        }
        event = self.mangleEventResult(event, result)
        self.log(event)

    def v2_runner_on_failed(self, result, **kwargs):
        event = {
            'event_type': "ansible_failed",
#            'userid': self.user,
            'session': self.session,
            'status': "FAILED",
            'ansible_type': "task",
            'ansible_playbook': self.playbook,
            'ansible_host': result._host.name,
            'ansible_task': result._task.name,
            'task_uuid': result._task._uuid,
#            'ansible_environment': self.environment
            #'ansible_task_result': self._dump_results(result._result)
        }
        event = self.mangleEventResult(event, result)
        self.errors += 1
        self.log(event)

    def v2_runner_on_unreachable(self, result, **kwargs):
        event = {
            'event_type': "ansible_unreachable",
#            'userid': self.user,
            'session': self.session,
            'status': "UNREACHABLE",
            'ansible_type': "task",
            'ansible_playbook': self.playbook,
            'ansible_host': result._host.name,
            'ansible_task': result._task.name,
            'task_uuid': result._task._uuid,
#            'ansible_environment': self.environment
            #'ansible_task_result': self._dump_results(result._result)
        }
        event = self.mangleEventResult(event, result)
        self.errors += 1
        self.log(event)

    def v2_runner_on_async_failed(self, result, **kwargs):
        event = {
            'event_type': "ansible_async",
#            'userid': self.user,
            'session': self.session,
            'status': "FAILED",
            'ansible_type': "task",
            'ansible_playbook': self.playbook,
            'ansible_host': result._host.name,
            'ansible_task': result._task.name,
            'task_uuid': result._task._uuid,
#            'ansible_environment': self.environment
            #'ansible_task_result': self._dump_results(result._result)
        }
        event = self.mangleEventResult(event, result)
        self.errors += 1
        self.log(event)
