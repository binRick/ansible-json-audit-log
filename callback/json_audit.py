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

import os, time, pathlib
import pwd
import json
import uuid
from datetime import datetime
import collections

from ansible import context
from ansible.module_utils._text import to_bytes
from ansible.plugins.callback import CallbackBase
from ansible.parsing.ajson import AnsibleJSONEncoder

_INCLUDE_ROLES_LIST = True
_INCLUDE_TASKS_LIST = True
TASK_START_TIMES = {}
TASK_END_TIMES = {}
SESSION_UUID = os.environ.get('SESSION_UUID', str(uuid.uuid1()))
SERVER_UUID = os.environ.get('SERVER_UUID', str(uuid.uuid1()))
PLAY_UUID = os.environ.get('PLAY_UUID', str(uuid.uuid1()))
ANSIBLE_JSON_LOG_PATH = os.environ.get('ANSIBLE_JSON_LOG_PATH', '/tmp/ansible-audit.log')
PIPES =  [ANSIBLE_JSON_LOG_PATH]


def getTimestampMilliseconds():
    return int(time.time() * 1000)

def getTimestamp():
    return int(time.time())

def summarizeRoles(ROLES, TASKS):
    SUMMARY = {'roles': {}}
    if ROLES.tasks:
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



class CallbackModule(CallbackBase):
    """
    logs playbook results in /var/log/ansible/audit.log
    """
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'notification'
    CALLBACK_NAME = 'json_audit'
    CALLBACK_NEEDS_WHITELIST = True

    def __init__(self):
        self.vm = None
        self.tasks = collections.OrderedDict()
        self.roles = collections.OrderedDict()
        self.current = None
        self._PLAYBOOK_START_TS_MS = None
        self._PLAYBOOK_END_TS_MS = None
        self._DURATION_MS = None
        self._SKIPPED_TASKS = []
        super(CallbackModule, self).__init__()

        self.user = self.get_username()
        self.log_path = ANSIBLE_JSON_LOG_PATH
        self.session_uuid = SESSION_UUID
        self.errors = 0
        self.pid = os.getpid()
        self.start_time = getTimestampMilliseconds()
        self.environment = None
        self.playbook = None
        self.play = None
        self.start_logged = False
        self._host_counter = None
        self._task_counter = None
        self._host_total = None
        self._task_total = None

    def baseEvent(self, event):
        event['ts_ms'] = getTimestampMilliseconds()
        if self._task_counter:
            event['task_counter'] = self._task_counter
        return event

    def mangleEventResult(self, event, result):
        event['changed'] =  result.is_changed()
        if result._task.no_log:
            event['no_log'] = True
        else:
            event['no_log'] = False
        return event

    def _all_vars(self, host=None, task=None):
        # host and task need to be specified in case 'magic variables' (host vars, group vars, etc)
        # need to be loaded as well
        return self.play.get_variable_manager().get_vars(
            play=self.play,
            host=host,
            task=task
        )


    def _record_task(self, task):
        self.current = task._uuid
        self.tasks[self.current] = {}
        self.tasks[self.current]['name'] = task.get_name().strip()
        if self.current not in TASK_START_TIMES.keys():
            TASK_START_TIMES[self.current] = getTimestampMilliseconds()
        else:
            TASK_END_TIMES[self.current] = getTimestampMilliseconds()
            self.tasks[self.current]['start_ts_ms'] = TASK_START_TIMES[self.current]
            self.tasks[self.current]['end_ts_ms'] = TASK_END_TIMES[self.current]
            self.tasks[self.current]['duration_ms'] = TASK_END_TIMES[self.current] - TASK_START_TIMES[self.current]

        if task.action:
            self.tasks[self.current]['action'] = task.action

        if task._role:
            self.tasks[self.current]['role'] = task._role._role_name
            if not task._role._role_name in self.roles:
                self.roles[task._role._role_name] = {'tasks': [], 'total_ms': 0}
            if not task._uuid in self.roles[task._role._role_name]['tasks']:
                self.roles[task._role._role_name]['tasks'].append(task._uuid)

        if self._display.verbosity >= 2:
            self.tasks[self.current]['path'] = task.get_path()

    def get_username(self):
        return pwd.getpwuid(os.getuid())[0]

    def log(self, event):
        event = self.baseEvent(event)
        event['play_uuid'] = PLAY_UUID
        event['server_uuid'] = SERVER_UUID
        event['session_uuid'] = SESSION_UUID
        event['pid'] = self.pid
        event['user'] = self.user
        event['playbook'] = self.playbook


        if 'task_uuid' in event.keys() and 'role' in self.tasks[event['task_uuid']].keys() and self.tasks[event['task_uuid']]['role']:
            event['role'] = self.tasks[event['task_uuid']]['role'] 

        if 'task_uuid' in event.keys() and event['task_uuid'] in TASK_START_TIMES:
            event['start_ts_ms'] = TASK_START_TIMES[event['task_uuid']]

        if 'task_uuid' in event.keys() and event['task_uuid'] in TASK_END_TIMES:
            event['end_ts_ms'] = TASK_END_TIMES[event['task_uuid']]
            event['duration_ms'] = event['end_ts_ms'] - event['start_ts_ms']

        msg = to_bytes(json.dumps(event, cls=AnsibleJSONEncoder) + "\n")

        path = os.path.realpath(os.path.dirname(os.path.realpath(self.log_path)))
        if not os.path.exists(path):
            pathlib.Path(path).mkdir(parents=True, exist_ok=True)

        with open(self.log_path, "ab") as fd:
            fd.write(msg)

    def v2_playbook_on_handler_task_start(self, task):
        self._record_task(task)
        event = {
            'event_type': "task_handler_start",
            'task_uuid': task._uuid,
        }
        if task._role:
            event['role'] = task._role._role_name
        if task and task.name:
            event['ansible_task'] = task.name

        self.log(event)

    """ Event used when host begins execution of a task """
    """
    def v2_runner_on_start(self, host, task):
        self._record_task(task)
        event = {
            'event_type': "__start",
            'task_uuid': task._uuid,
        }
        if task._role:
            event['role'] = task._role._role_name
        if task and task.name:
            event['ansible_task'] = task.name

        #self.log(event)
    """

    def v2_runner_on_start(self, host, task):
        self._record_task(task)
    def v2_playbook_on_task_start(self, task, is_conditional):
        self._task_counter += 1
        self._PLAYBOOK_START_TS_MS = getTimestampMilliseconds()
        self._record_task(task)
        event = {
            'event_type': "task_start",
            'is_conditional': is_conditional,
            'task_uuid': task._uuid,
        }

        if task._role:
            event['role'] = task._role._role_name
        if task and task.name:
            event['ansible_task'] = task.name

        if task._role and task._role._role_name:
            event['role'] = task._role._role_name
            if not event['role'] in self.roles.keys():
                self.roles[event['role']] = []
            if not task._uuid in self.roles[event['role']]['tasks']:
                self.roles[event['role']]['tasks'].append(task._uuid)
        self.log(event)

    def v2_playbook_on_play_start(self, play):
        self.play = play
        play_name = play.get_name().strip()
        self.vm = play.get_variable_manager()
        self._host_total = len(self._all_vars()['vars']['ansible_play_hosts_all'])
        self._task_total = len(self.play.get_tasks()[0])
        self._task_counter = 0

        event = {
              'event_type': "start",
              'status': "OK",
              '_type': "start",
              '_host_total': self._host_total,
              '_task_total': self._task_total,
        }
        if not self.start_logged:
          self.start_logged = True

        self.log(event)



    def v2_playbook_on_start(self, playbook):
        path, filename = os.path.split(os.path.join(playbook._basedir, playbook._file_name))
        #self.playbook = os.path.join(os.path.split(path)[1], filename)
        self.playbook = filename
        event = {
              'event_type': "playbook_start",
              'status': "OK",
              'ts_ms': getTimestampMilliseconds(),
              '_type': "start",
              'tags': context.CLIARGS['tags'],
              'skip_tags': context.CLIARGS['skip_tags'],
              'extra_vars': context.CLIARGS['extra_vars'],
              'subset': context.CLIARGS['subset'],
              'inventory': context.CLIARGS['inventory'],
              'remote_user': context.CLIARGS['remote_user'],
#              'cli_args': context.CLIARGS,
        }
        self.log(event)



    def v2_playbook_on_stats(self, stats):
        self._PLAYBOOK_END_TS_MS = getTimestampMilliseconds()
        self._DURATION_MS = self._PLAYBOOK_END_TS_MS - self.start_time

        summarized = {}
        HOSTS = sorted(stats.processed.keys())

        if len(HOSTS) == 1:
            host = HOSTS[0]
            s = stats.summarize(host)
            summarized[host] = {}
            for k in ['ok', 'changed', 'unreachable','failures', 'rescued', 'ignored']:
                summarized[host][k] = 0
                if k in s.keys():
                    summarized[host][k] = s[k]

        else:
            for host in HOSTS:
                s = stats.summarize(host)
                summarized[host] = {}
                for k in ['ok', 'changed', 'unreachable','failures', 'rescued', 'ignored']:
                    summarized[host][k] = 0
                    if k in s.keys():
                        summarized[host][k] = s[k]



        if self.errors == 0:
            status = "OK"
        else:
            status = "FAILED"

        event = {
            'event_type': "stats",
            '_type': "finish",
            'status': status,
            'start_ts_ms':  self._PLAYBOOK_START_TS_MS,
            'end_ts_ms':  self._PLAYBOOK_END_TS_MS,
            'errors': self.errors,
            'duration_ts_ms':  self._DURATION_MS,
            'ts_ms': getTimestampMilliseconds(),
            'roles': [],
            'tasks': [],
            'skipped_tasks': self._SKIPPED_TASKS,
            'summarized': summarized,
        }

        if _INCLUDE_ROLES_LIST:
            if self.roles:
                event['roles'] = self.roles

        if _INCLUDE_TASKS_LIST:
            if self.tasks:
                event['tasks'] = self.tasks

#        if self.tasks and self.roles:
#            event['summarizeRoles'] = summarizeRoles(self.roles,self.tasks)

        self.log(event)


    def v2_runner_on_ok(self, result, **kwargs):
        COUNTER_MSG = ("%d/%d [%s]" % (self._task_counter, self._task_total, result._task.get_name().strip()))
        event = {
            'event_type': "task_ok",
            'status': "OK",
            '_type': "task",
            'host': result._host.name,
            'ansible_task': result._task.name,
            'task_uuid': result._task._uuid,
            'check_mode': ('ansible_check_mode' in self.vm.get_vars().keys()),
            'COUNTER_MSG': COUNTER_MSG,
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
        if not result._task._uuid in self._SKIPPED_TASKS:
            self._SKIPPED_TASKS.append(result._task._uuid)
        event = {
            'event_type': "task_skipped",
            'status': "SKIPPED",
            '_type': "task",
            'ansible_task': result._task.name,
            'host': result._host.name,
            'task_uuid': result._task._uuid,
        }
        try:
            event = self.mangleEventResult(event, result)
        except Exception as e:
            pass

        if result._task._role and result._task._role:
            event['role'] = result._task._role._role_name

        self.log(event)

    def v2_playbook_on_import_for_host(self, result, imported_file):
        event = {
            'event_type': "ansible_import",
            'status': "IMPORTED",
            '_type': "import",
            'host': result._host.name,
            'ansible_imported_file': imported_file,
            'task_uuid': result._task._uuid,
        }
        event = self.mangleEventResult(event, result)
        self.log(event)

    def v2_playbook_on_not_import_for_host(self, result, missing_file):
        event = {
            'event_type': "ansible_import",
            'status': "FAILED",
            '_type': "task",
            'host': result._host.name,
            'ansible_task': result._task.name,
            'task_uuid': result._task._uuid,
        }
        event = self.mangleEventResult(event, result)
        self.errors += 1
        self.log(event)

    def v2_runner_on_unreachable(self, result, **kwargs):
        event = {
            'event_type': "task_unreachable",
            'status': "unreachable",
            '_type': "task",
            'host': result._host.name,
            'ansible_task': result._task.name,
            'task_uuid': result._task._uuid,
        }
        event = self.mangleEventResult(event, result)
        self.errors += 1
        self.log(event)

    def v2_runner_on_async_failed(self, result, **kwargs):
        event = {
            'event_type': "async",
            'status': "failed",
            '_type': "task",
            'host': result._host.name,
            'ansible_task': result._task.name,
            'task_uuid': result._task._uuid,
        }
        event = self.mangleEventResult(event, result)
        self.errors += 1
        self.log(event)
