from fabric.api import run, env, cd, put, get, execute, require, sudo, local, lcd, settings
from fabric.decorators import runs_once, roles, parallel


from base64 import b64encode, b64decode
import rscoin

import sys
sys.path += [ "." ]

import re
import boto3
ec2 = boto3.resource('ec2')


def get_aws_machines():
    instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    return ['ubuntu@' + i.public_dns_name for i in instances]

def parse_machines(s):
    urls = re.findall("ec2-.*.compute.amazonaws.com", s)
    names = [('ubuntu@' + u) for u in urls ]
    return names


all_machines = get_aws_machines()
servers = all_machines[:len(all_machines) / 2]
clients = all_machines[len(all_machines) / 2:]


def dyn_server_role():
    if "slimit" not in env:
        return servers
    else:
        return servers[:env.slimit]


env.roledefs.update({
    'servers': dyn_server_role, #servers,
    'clients': clients
})

from collections import defaultdict
env.timings = defaultdict(list)

NUM_MACHINES = 10

@runs_once
def ec2start():
    if len(all_machines) < NUM_MACHINES:
        missing = NUM_MACHINES - len(all_machines)
        ec2.create_instances(
            ImageId='ami-178be960', 
            InstanceType='t2.micro',
            SecurityGroupIds= [ 'sg-ae5f0fcb' ],
            MinCount=missing, 
            MaxCount=missing )

@runs_once
def ec2list():
    instances = ec2.instances.all()
    for instance in instances:
        print(instance.id, instance.state["Name"], instance.public_dns_name)


@runs_once
def ec2stop():
    instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    ids = [i.id for i in instances]
    try:
        ec2.instances.filter(InstanceIds=ids).stop()
        ec2.instances.filter(InstanceIds=ids).terminate()
    except Exception as e:
        print e

@roles("servers")
def time():
    with cd('/home/ubuntu/projects/rscoin/src'):
        x = run('py.test-2.7 -s -k "full_client"') + "\n\n"
        x += run('py.test-2.7 -s -k "timing"')
        
        for k, v in re.findall("(.*:) (.*) / sec", x):
            env.timings[k] += [ float(v) ]


        import numpy as np

        f = file("remote_timings.txt", "w")
        for k, v in env.timings.iteritems():
            f.write("%s %2.4f %2.4f\n" % (k, np.mean(v), np.std(v)))            

def null():
    pass

@roles("servers","clients")
def gitpull():
    with cd('/home/ubuntu/projects/rscoin/src'):
        # run('git commit -m "merge" -a')
        run('git pull')

@roles("servers", "clients")
@parallel
def gitall():
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

@roles("servers", "clients")
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
@parallel
def loaddir():
    with cd('/home/ubuntu/projects/rscoin/src'):
        put('directory.conf', 'directory.conf')

@roles("clients")
@parallel
def loadsecret():
    with cd('/home/ubuntu/projects/rscoin/src'):
        put('secret.key', 'secret.key')


@roles("servers","clients")
@parallel
def passcache():
    put('known_hosts', '~/.ssh/known_hosts')
    with cd('/home/ubuntu/projects/rscoin/.git'):
        sudo('touch ~/.ssh/id_rsa && rm ~/.ssh/id_rsa')
        put('~/.ssh/id_rsa', '~/.ssh/id_rsa')
        run('chmod 600 ~/.ssh/id_rsa')
        put('../.git/config', 'config')

    with cd('/home/ubuntu/projects/rscoin/src'):
        sudo('pip install petlib --upgrade')
        run("git pull")

@runs_once
def init():
    local("grep rsa ~/.ssh/known_hosts > known_hosts")
    execute(passcache)

def runcollect():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run("collectl -f LOGFILE -D")
        num = run("ps -A | grep collect")
        print re.findall("[0-9]+", num)[0]
        run("kill %s" % num)


@runs_once
def deploy():
    execute(gitall)
    execute(keys)
    execute(loaddir)
    execute(loadsecret)

@runs_once
def experiment1():
    env.messages = 200
    env.expname = "experiment1"
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
        run("python simscript.py %s payments.txt" % env.messages)
        run("rm -rf %s" % env.expname)
        run("mkdir %s" % env.expname)
        run("./rsc.py --play payments.txt-issue > %s/issue-times.txt" % env.expname)
        # run("./rsc.py --play payments.txt-r1 > experiment1/r1-times.txt")

@roles("clients")
@parallel
def experiment1pre():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run("./rsc.py --play payments.txt-r1 > %s/r1-times.txt" % env.expname)


@roles("clients")
@parallel
def experiment1actual():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run("./rsc.py --play payments.txt-r2 --conn 20 > %s/r2-times.txt" % env.expname)


@roles("clients")
def experiment1collect():        
        # run("ls experiment1/*")
    with cd('/home/ubuntu/projects/rscoin/src/%s' % env.expname):
        get('issue-times.txt', '%s/%s-issue-times.txt' % (env.expname, env.host))

    with lcd(env.expname):
        local("cat %s-issue-times.txt >> issue-times.txt" % env.host)

    with cd('/home/ubuntu/projects/rscoin/src/%s' % env.expname):
        get('r1-times.txt', '%s/%s-r1-times.txt' % (env.expname, env.host))
    
    with lcd(env.expname):
        local("cat %s-r1-times.txt >> r1-times.txt" % env.host)

    with cd('/home/ubuntu/projects/rscoin/src/%s' % env.expname):
        get('r2-times.txt', '%s/%s-r2-times.txt' % (env.expname, env.host))

    with lcd(env.expname):
        local("cat %s-r2-times.txt >> r2-times.txt" % env.host)

        # local("python exp1plot.py experiment1")

@runs_once
def experiment2():
    local("rm -rf experiment2")
    local("mkdir experiment2")

    local("python simscript.py 2000 payments.txt")
    local("./rsc.py --play payments.txt-issue > experiment2/issue-times.txt")
    local("./rsc.py --play payments.txt-r1 --conn 20 > experiment2/r1-times.txt")
    local("./rsc.py --play payments.txt-r2 > experiment2/r2-times.txt")

    local("python exp1plot.py experiment2")


@runs_once
def experiment3():

    env.messages = 1000

    for i in range(1, len(servers)+1):

        env.expname = "experiment3x%03d" % i
        with settings(warn_only=True):
            local( "rm -rf %s" % env.expname )
        local( "mkdir %s" % env.expname )


        print (str(i) + " ") * 10
        env.slimit = i
        # execute(exp3each)

        with settings(warn_only=True):
            execute(stop)

        with settings(warn_only=True):            
            execute(clean)
        
        if "rsdir" in env:
            del env["rsdir"]
        execute(keys)
        execute(loaddir)
        execute(loadsecret)

        execute(start)

        execute( experiment1run )
        execute( experiment1pre )

        execute( experiment1actual )
        execute( experiment1collect )


        with settings(warn_only=True):
            execute(stop)

        local("python exp1plot.py %s" % env.expname)
        local("python estthroughput.py %s > %s/stats.txt" % (env.expname, env.expname))



@roles("servers")
def exp3each():
    print "Hello: %s" % env.host
    execute(keys)
    execute(loaddir)
