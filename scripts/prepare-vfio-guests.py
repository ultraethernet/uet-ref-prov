#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Create isolated cloud-init seeds and qcow2 overlays; never boot a guest."""
import json
import pathlib
import subprocess
import sys

lab = pathlib.Path(sys.argv[1]).resolve()
image = lab / 'images/ubuntu-26.04-amd64.qcow2'
runtime = lab / 'runtime'
runtime.mkdir(exist_ok=True)
key = runtime / 'guest_key'
if not key.exists():
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
public_key = key.with_suffix('.pub').read_text().strip()
for side, number in [('a', 1), ('b', 2)]:
    directory = runtime / side
    directory.mkdir(exist_ok=True)
    disk = directory / 'guest.qcow2'
    if not disk.exists():
        subprocess.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2',
                        '-b', str(image), str(disk), '12G'], check=True)
    userdata = {
        'hostname': 'uet-vfio-' + side,
        'manage_etc_hosts': True,
        'users': [{'name': 'uet', 'groups': ['sudo'],
                   'sudo': 'ALL=(ALL) NOPASSWD:ALL', 'shell': '/bin/bash',
                   'ssh_authorized_keys': [public_key]}],
        'ssh_pwauth': False,
        'package_update': False,
        'packages': ['libnl-3-200', 'libnl-route-3-200', 'libudev1'],
        'runcmd': [['systemctl', 'disable', '--now', 'unattended-upgrades.service']],
    }
    network = {'version': 2, 'ethernets': {
        'mgmt0': {'match': {'macaddress': f'52:54:00:55:00:0{number}'},
                  'set-name': 'mgmt0', 'dhcp4': True, 'dhcp6': False},
    }}
    (directory / 'user-data').write_text('#cloud-config\n' + json.dumps(userdata, indent=2) + '\n')
    (directory / 'meta-data').write_text(json.dumps({
        'instance-id': f'uet-vfio-{side}', 'local-hostname': f'uet-vfio-{side}'}))
    (directory / 'network-config').write_text(json.dumps(network, indent=2))
    seed = directory / 'seed.img'
    if not seed.exists():
        subprocess.run(['cloud-localds', '--network-config=' + str(directory / 'network-config'),
                        str(seed), str(directory / 'user-data'),
                        str(directory / 'meta-data')], check=True)
    print(f'Prepared guest {side}: {disk}')
