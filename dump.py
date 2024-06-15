#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import codecs
import frida
import threading
import os
import shutil
import time
import argparse
import tempfile
import subprocess
import re
import paramiko
from paramiko import SSHClient
from scp import SCPClient
from tqdm import tqdm
import traceback
from functools import cmp_to_key

script_dir = os.path.dirname(os.path.realpath(__file__))
DUMP_JS = os.path.join(script_dir, 'dump.js')

DEFAULT_USER = 'root'
DEFAULT_PASSWORD = 'alpine'
DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 2222

TEMP_DIR = tempfile.gettempdir()
PAYLOAD_DIR = 'Payload'
PAYLOAD_PATH = os.path.join(TEMP_DIR, PAYLOAD_DIR)
file_dict = {}

finished = threading.Event()

def get_usb_iphone():
    Type = 'usb' if int(frida.__version__.split('.')[0]) >= 12 else 'tether'
    device_manager = frida.get_device_manager()
    changed = threading.Event()

    def on_changed():
        changed.set()

    device_manager.on('changed', on_changed)
    device = None

    while device is None:
        devices = [dev for dev in device_manager.enumerate_devices() if dev.type == Type]
        if not devices:
            print('Waiting for USB device...')
            changed.wait()
        else:
            device = devices[0]

    device_manager.off('changed', on_changed)
    return device

def generate_ipa(path, display_name):
    ipa_filename = f'{display_name}.ipa'
    print(f'Generating "{ipa_filename}"')
    try:
        app_name = file_dict['app']
        for key, value in file_dict.items():
            from_dir = os.path.join(path, key)
            to_dir = os.path.join(path, app_name, value)
            if key != 'app':
                shutil.move(from_dir, to_dir)

        target_dir = f'./{PAYLOAD_DIR}'
        subprocess.check_call(['zip', '-qr', os.path.join(os.getcwd(), ipa_filename), target_dir], cwd=TEMP_DIR)
        shutil.rmtree(PAYLOAD_PATH)
    except Exception as e:
        print(e)
        finished.set()

def on_message(message, data):
    t = tqdm(unit='B', unit_scale=True, unit_divisor=1024, miniters=1)
    last_sent = [0]

    def progress(filename, size, sent):
        baseName = os.path.basename(filename)
        t.desc = baseName.decode("utf-8") if isinstance(baseName, bytes) else baseName
        t.total = size
        t.update(sent - last_sent[0])
        last_sent[0] = 0 if size == sent else sent

    if 'payload' in message:
        payload = message['payload']
        if 'dump' in payload:
            origin_path = payload['path']
            dump_path = payload['dump']
            scp_from = dump_path
            scp_to = f'{PAYLOAD_PATH}/'

            with SCPClient(ssh.get_transport(), progress=progress, socket_timeout=60) as scp:
                scp.get(scp_from, scp_to)

            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(dump_path))
            try:
                subprocess.check_call(['chmod', '655', chmod_dir])
            except subprocess.CalledProcessError as err:
                print(err)

            index = origin_path.find('.app/')
            file_dict[os.path.basename(dump_path)] = origin_path[index + 5:]

        if 'app' in payload:
            app_path = payload['app']
            scp_from = app_path
            scp_to = f'{PAYLOAD_PATH}/'
            with SCPClient(ssh.get_transport(), progress=progress, socket_timeout=60) as scp:
                scp.get(scp_from, scp_to, recursive=True)

            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(app_path))
            try:
                subprocess.check_call(['chmod', '755', chmod_dir])
            except subprocess.CalledProcessError as err:
                print(err)

            file_dict['app'] = os.path.basename(app_path)

        if 'done' in payload:
            finished.set()
    t.close()

def compare_applications(a, b):
    a_is_running, b_is_running = a.pid != 0, b.pid != 0
    if a_is_running == b_is_running:
        return (a.name > b.name) - (a.name < b.name)
    return -1 if a_is_running else 1

def get_applications(device):
    try:
        return device.enumerate_applications()
    except Exception as e:
        sys.exit(f'Failed to enumerate applications: {e}')

def list_applications(device):
    applications = get_applications(device)
    if applications:
        pid_width = max(len(f'{app.pid}') for app in applications)
        name_width = max(len(app.name) for app in applications)
        id_width = max(len(app.identifier) for app in applications)
    else:
        pid_width = name_width = id_width = 0

    header_format = f'%{pid_width}s  %-{name_width}s  %-{id_width}s'
    print(header_format % ('PID', 'Name', 'Identifier'))
    print(f'{"-"*pid_width}  {"-"*name_width}  {"-"*id_width}')
    line_format = f'%{pid_width}s  %-{name_width}s  %-{id_width}s'
    for app in sorted(applications, key=cmp_to_key(compare_applications)):
        pid_display = '-' if app.pid == 0 else f'{app.pid}'
        print(line_format % (pid_display, app.name, app.identifier))

def load_js_file(session, filename):
    with codecs.open(filename, 'r', 'utf-8') as f:
        script = session.create_script(f.read())
    script.on('message', on_message)
    script.load()
    return script

def create_dir(path):
    if os.path.exists(path):
        shutil.rmtree(path)
    try:
        os.makedirs(path)
    except os.error as err:
        print(err)

def open_target_app(device, name_or_bundleid):
    print(f'Start the target app {name_or_bundleid}')
    session = None
    display_name = bundle_identifier = ''
    for app in get_applications(device):
        if name_or_bundleid in (app.identifier, app.name):
            pid = app.pid or device.spawn([app.identifier])
            session = device.attach(pid)
            if not app.pid:
                device.resume(pid)
            display_name = app.name
            bundle_identifier = app.identifier
            break
    return session, display_name, bundle_identifier

def start_dump(session, ipa_name):
    print(f'Dumping {ipa_name} to {TEMP_DIR}')
    script = load_js_file(session, DUMP_JS)
    script.post('dump')
    finished.wait()
    generate_ipa(PAYLOAD_PATH, ipa_name)
    if session:
        session.detach()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='frida-ios-dump (by AloneMonkey v2.0)')
    parser.add_argument('-l', '--list', dest='list_applications', action='store_true', help='List the installed apps')
    parser.add_argument('-o', '--output', dest='output_ipa', help='Specify name of the decrypted IPA')
    parser.add_argument('-H', '--host', dest='ssh_host', default=DEFAULT_HOST, help='Specify SSH hostname')
    parser.add_argument('-p', '--port', dest='ssh_port', type=int, default=DEFAULT_PORT, help='Specify SSH port')
    parser.add_argument('-u', '--user', dest='ssh_user', default=DEFAULT_USER, help='Specify SSH username')
    parser.add_argument('-P', '--password', dest='ssh_password', default=DEFAULT_PASSWORD, help='Specify SSH password')
    parser.add_argument('-K', '--key_filename', dest='ssh_key_filename', help='Specify SSH private key file path')
    parser.add_argument('target', nargs='?', help='Bundle identifier or display name of the target app')

    args = parser.parse_args()
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        device = get_usb_iphone()
        if args.list_applications:
            list_applications(device)
        else:
            ssh.connect(args.ssh_host, port=args.ssh_port, username=args.ssh_user, password=args.ssh_password, key_filename=args.ssh_key_filename)
            create_dir(PAYLOAD_PATH)
            session, display_name, bundle_identifier = open_target_app(device, args.target)
            output_ipa = re.sub(r'\.ipa$', '', args.output_ipa or display_name)
            if session:
                start_dump(session, output_ipa)
    except Exception as e:
        print(f'Error: {e}')
        traceback.print_exc()
    finally:
        if ssh:
            ssh.close()
        if os.path.exists(PAYLOAD_PATH):
            shutil.rmtree(PAYLOAD_PATH)
