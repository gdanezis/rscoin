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
    i-d08b917b: ec2-54-72-70-139.eu-west-1.compute.amazonaws.com
    i-d18b917a: ec2-54-72-14-117.eu-west-1.compute.amazonaws.com
    i-d28b9179: ec2-54-72-38-66.eu-west-1.compute.amazonaws.com
    i-d38b9178: ec2-54-72-46-150.eu-west-1.compute.amazonaws.com
    i-d48b917f: ec2-54-72-32-83.eu-west-1.compute.amazonaws.com
    i-d58b917e: ec2-54-72-17-217.eu-west-1.compute.amazonaws.com
    i-d68b917d: ec2-54-72-24-217.eu-west-1.compute.amazonaws.com
    i-d78b917c: ec2-54-72-24-54.eu-west-1.compute.amazonaws.com
    i-dc8b9177: ec2-54-72-42-95.eu-west-1.compute.amazonaws.com
    i-de8b9175: ec2-54-72-44-202.eu-west-1.compute.amazonaws.com
    i-df8b9174: ec2-54-72-12-42.eu-west-1.compute.amazonaws.com
    i-e08b914b: ec2-54-72-43-236.eu-west-1.compute.amazonaws.com
    i-e18b914a: ec2-54-72-61-251.eu-west-1.compute.amazonaws.com
""")

clients = parse_machines("""
    i-e38b9148: ec2-54-72-30-210.eu-west-1.compute.amazonaws.com
    i-e48b914f: ec2-54-72-53-255.eu-west-1.compute.amazonaws.com
    i-e58b914e: ec2-54-72-43-51.eu-west-1.compute.amazonaws.com
    i-e68b914d: ec2-52-16-61-154.eu-west-1.compute.amazonaws.com
    i-e78b914c: ec2-54-72-24-32.eu-west-1.compute.amazonaws.com
    i-fb8b9150: ec2-54-72-72-2.eu-west-1.compute.amazonaws.com
    i-e28b9149: ec2-54-72-35-182.eu-west-1.compute.amazonaws.com
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
@parallel
def start():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run('twistd -y rscserver.tac.py')

@roles("servers")
@parallel
def clean():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run('rm log-*')
        run('rm keys-*')

@roles("servers")
@parallel
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
    execute( "experiment1pre" )
    execute( "experiment1actual" )
    execute( "experiment1collect" )
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
        # run("./rsc.py --play payments.txt-r1 > experiment1/r1-times.txt")

@roles("clients")
@parallel
def experiment1pre():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run("./rsc.py --play payments.txt-r1 > experiment1/r1-times.txt")


@roles("clients")
@parallel
def experiment1actual():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run("./rsc.py --play payments.txt-r2 --conn 50 > experiment1/r2-times.txt")


@roles("clients")
def experiment1collect():        
        # run("ls experiment1/*")
    with cd('/home/ubuntu/projects/rscoin/src'):
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

    local("python simscript.py 2000 payments.txt")
    local("./rsc.py --play payments.txt-issue > experiment2/issue-times.txt")
    local("./rsc.py --play payments.txt-r1 > experiment2/r1-times.txt")
    local("./rsc.py --play payments.txt-r2 > experiment2/r2-times.txt")

    local("python exp1plot.py experiment2")
