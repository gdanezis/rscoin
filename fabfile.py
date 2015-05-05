from fabric.api import run, env, cd, put, execute, require, sudo, local
from fabric.decorators import runs_once


from base64 import b64encode, b64decode
import rscoin

import sys
sys.path += [ "." ]

import re
aws_str = """
    i-54c1f1b2: ec2-52-17-100-153.eu-west-1.compute.amazonaws.com
    i-55c1f1b3: ec2-52-17-47-246.eu-west-1.compute.amazonaws.com
    i-56c1f1b0: ec2-52-17-191-196.eu-west-1.compute.amazonaws.com
    i-57c1f1b1: ec2-52-17-98-120.eu-west-1.compute.amazonaws.com
    i-dac4f43c: ec2-52-17-36-157.eu-west-1.compute.amazonaws.com
"""

ulrs = re.findall("ec2-.*.compute.amazonaws.com", aws_str)


env.hosts = [('ubuntu@' + u) for u in ulrs ]


def null():
    pass

def gitpull():
    with cd('/home/ubuntu/projects/rscoin/src'):
        # run('git commit -m "merge" -a')
        sudo('pip install petlib --upgrade')
        run('git pull')

def host_type():
    run('uname -s')

def start():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run('twistd -y rscserver.tac.py')

def clean():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run('rm log-*')
        run('rm keys-*')

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
        sudo("apt-get install collectl")
        # sudo("/etc/init.d/collectl start -D")
        run("git config credential.helper store")
        run("git pull")

def runcollect():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run("collectl -f LOGFILE -D")
        num = run("ps -A | grep collect")
        print re.findall("[0-9]+", num)[0]
        run("kill %s" % num)

#    sudo("/etc/init.d/collectl start -D")

#def collect():
#    with cd('/home/ubuntu/projects/rscoin/src'):
#        run("ls /var/log/collectl/")
#        fname = run("ls /var/log/collectl/*.raw.gz")
#        # run("cat %s" % fname)
#        run("collectl -p %s -s cn" % fname)

@runs_once
def deploy():
    execute(gitpull)
    execute(keys)
    execute(loaddir)

@runs_once
def experiment1():
    local("python simscript.py 1000 payments.txt")
    local("rm -rf experiment1")
    local("mkdir experiment1")
    local("./rsc.py --play payments.txt-issue > experiment1/issue-times.txt")
    local("./rsc.py --play payments.txt-r1 > experiment1/r1-times.txt")
    local("./rsc.py --play payments.txt-r2 > experiment1/r2-times.txt")
    local("python exp1plot.py experiment1")


