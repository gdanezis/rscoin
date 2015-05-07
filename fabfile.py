from fabric.api import run, env, cd, put, get, execute, require, sudo, local
from fabric.decorators import runs_once, roles, parallel


from base64 import b64encode, b64decode
import rscoin

import sys
sys.path += [ "." ]

import re

def parse_machines(s):
    urls = re.findall("ec2-.*.compute.amazonaws.com", s)
    names = [('ubuntu@' + u) for u in urls ]
    return names


servers = parse_machines("""
    i-c06d6e27: ec2-54-72-1-135.eu-west-1.compute.amazonaws.com
    i-c16d6e26: ec2-52-17-146-130.eu-west-1.compute.amazonaws.com
    i-c26d6e25: ec2-54-76-28-34.eu-west-1.compute.amazonaws.com
    i-c36d6e24: ec2-54-72-236-87.eu-west-1.compute.amazonaws.com
    i-c46d6e23: ec2-52-17-63-24.eu-west-1.compute.amazonaws.com
    i-c56d6e22: ec2-54-72-27-165.eu-west-1.compute.amazonaws.com
    i-c66d6e21: ec2-54-76-21-223.eu-west-1.compute.amazonaws.com
    i-c76d6e20: ec2-54-76-21-219.eu-west-1.compute.amazonaws.com
    i-c86d6e2f: ec2-54-72-208-211.eu-west-1.compute.amazonaws.com
    i-c96d6e2e: ec2-54-72-245-162.eu-west-1.compute.amazonaws.com
    i-ca6d6e2d: ec2-52-17-120-159.eu-west-1.compute.amazonaws.com
    i-cb6d6e2c: ec2-52-17-253-59.eu-west-1.compute.amazonaws.com
""")

clients = parse_machines("""
    i-f2b2b215: ec2-52-17-190-122.eu-west-1.compute.amazonaws.com
    i-f3b2b214: ec2-52-17-176-62.eu-west-1.compute.amazonaws.com
    i-fcb2b21b: ec2-52-17-213-23.eu-west-1.compute.amazonaws.com
    i-fdb2b21a: ec2-52-17-148-178.eu-west-1.compute.amazonaws.com
    i-feb2b219: ec2-52-17-166-42.eu-west-1.compute.amazonaws.com
    i-ffb2b218: ec2-52-17-243-128.eu-west-1.compute.amazonaws.com
""")

env.roledefs.update({
    'servers': servers,
    'clients': clients
})


def null():
    pass

@roles("servers","clients")
def gitpull():
    with cd('/home/ubuntu/projects/rscoin/src'):
        # run('git commit -m "merge" -a')
        run('git pull')

@roles("servers","clients")
def host_type():
    run('uname -s')

@roles("servers")
def start():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run('twistd -y rscserver.tac.py')

@roles("servers")
def clean():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run('rm log-*')
        run('rm keys-*')

@roles("servers")
def stop():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run('kill `cat twistd.pid`')

@roles("servers")
def keys():
    if "rsdir" not in env:
        secret = file("secret.key").read()
        public = rscoin.Key(secret, public=False)
        pid = b64encode(public.id())

        env["rsdir"] = {"special": pid, "directory": []}

    [_, host] = env.host_string.split("@")
    with cd('/home/ubuntu/projects/rscoin/src'):
        run('touch secret.key')
        run('rm secret.key')
        result = run('python derivekey.py --store')
        [_, key] = result.strip().split()
        
        kid = b64encode(rscoin.Key(b64decode(key)).id())
        env["rsdir"]["directory"] += [ [kid, host, 8080] ]
    

    from json import dumps
    file("directory.conf", "w").write(dumps(env["rsdir"]))

@roles("servers","clients")
def loaddir():
    with cd('/home/ubuntu/projects/rscoin/src'):
        put('directory.conf', 'directory.conf')

@roles("clients")
def loadsecret():
    with cd('/home/ubuntu/projects/rscoin/src'):
        put('secret.key', 'secret.key')


@roles("servers","clients")
def passcache():
    with cd('/home/ubuntu/projects/rscoin/.git'):
        sudo('touch ~/.ssh/id_rsa && rm ~/.ssh/id_rsa')
        put('~/.ssh/id_rsa', '~/.ssh/id_rsa')
        run('chmod 600 ~/.ssh/id_rsa')
        put('../.git/config', 'config')

    with cd('/home/ubuntu/projects/rscoin/src'):
        sudo('pip install petlib --upgrade')
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
    execute(loadsecret)

@runs_once
def experiment1():
    local( "rm -rf experiment1" )
    local( "mkdir experiment1" )
    execute( "experiment1run" )
    # local( "mkdir experiment1" )
    local("python exp1plot.py experiment1")

@roles("clients")
@parallel
def experiment1run():
    # local('sudo sysctl -w net.ipv4.ip_local_port_range="500   65535"')
    # local("sudo echo 20000500 > /proc/sys/fs/nr_open")
    # local('sudo sh -c "ulimit -n 1048576"')
    with cd('/home/ubuntu/projects/rscoin/src'):
        run("python simscript.py 2000 payments.txt")
        run("rm -rf experiment1")
        run("mkdir experiment1")
        run("./rsc.py --play payments.txt-issue > experiment1/issue-times.txt")
        run("./rsc.py --play payments.txt-r1 > experiment1/r1-times.txt")
        run("./rsc.py --play payments.txt-r2 > experiment1/r2-times.txt")
        
        # run("ls experiment1/*")
        get('experiment1/issue-times.txt', 'experiment1/%s-issue-times.txt' % env.host)
        local("cat experiment1/%s-issue-times.txt >> experiment1/issue-times.txt" % env.host)

        get('experiment1/r1-times.txt', 'experiment1/%s-r1-times.txt' % env.host)
        local("cat experiment1/%s-r1-times.txt >> experiment1/r1-times.txt" % env.host)

        get('experiment1/r2-times.txt', 'experiment1/%s-r2-times.txt' % env.host)
        local("cat experiment1/%s-r2-times.txt >> experiment1/r2-times.txt" % env.host)

        # local("python exp1plot.py experiment1")

@runs_once
def experiment2():
    local("rm -rf experiment2")
    local("mkdir experiment2")

    local("python simscript.py 300 payments.txt")
    local("./rsc.py --play payments.txt-issue > experiment2/issue-times.txt")
    local("./rsc.py --play payments.txt-r1 > experiment2/r1-times.txt")
    local("./rsc.py --play payments.txt-r2 > experiment2/r2-times.txt")

    local("python exp1plot.py experiment2")
