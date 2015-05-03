from fabric.api import run, env, cd, put, execute, require
from fabric.decorators import runs_once


import sys
sys.path += ["."]

import rscoin
from base64 import b64encode, b64decode


env.hosts = ['ubuntu@52.17.186.0', 
             'ubuntu@52.17.179.62',
             'ubuntu@52.17.183.156',
             'ubuntu@52.17.55.88',
             'ubuntu@52.17.186.209',]

from fabric.network import prompt_for_password

def gitpull():
    with cd('/home/ubuntu/projects/rscoin/src'):
        # run('git commit -m "merge" -a')
        run('echo %s | git pull' % env["git_pass"])

def host_type():
    run('uname -s')

def start():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run('twistd -y rscserver.tac.py')

def stop():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run('kill `cat twistd.pid`')

def keys():
    if "rsdir" not in env:
        secret = file("secret.key").read()
        public = rscoin.Key(secret, public=False)
        pid = b64encode(public.id())

        env["rsdir"] = {"special": pid, "directory": []}

    [_, host] = env.host_string.split("@")
    with cd('/home/ubuntu/projects/rscoin/src'):
        result = run('python derivekey.py --store')
        [_, key] = result.strip().split()
        
        kid = b64encode(rscoin.Key(b64decode(key)).id())
        env["rsdir"]["directory"] += [ [kid, host, 8080] ]
    

    from json import dumps
    file("directory.conf", "w").write(dumps(env["rsdir"]))

def loaddir():
    with cd('/home/ubuntu/projects/rscoin/src'):
        put('directory.conf', 'directory.conf')


def passcache():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run("git config credential.helper store")
        run("git pull")

@runs_once
def deploy():
    execute(gitpull)
    execute(keys)
    execute(loaddir)