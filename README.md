# ansible-json-audit-log
This project provides a json formatted audit log for ansible

## Jenkins support
Audit logger tries to extract user identity from environment variable JEKNINS_USER. If variable is not set,
user identity is read from operating system.

## Known limitations
* A magic variable named environment_name must be defined in inventory. Use group_vars/all to set defaults.
* JENKINS_USER environment variable may be set by *any* user. If you are using this plugin for auditing, do
  not let non-privileged users to execute playbooks from your ansible controller directly.

## Configuration
1. Copy json_audit.py callback plugin to plugins directory (default: /usr/share/ansible/plugins/callback/)
2. Ensure that your inventory has environment_name variable set
3. Ensure that /var/log/ansible is writeable by user running ansible
4. Whitelist json_audit callback plugin:

        [defaults]
        bin_ansible_callbacks = True
        callback_whitelist = json_audit
