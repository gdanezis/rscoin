from fabric.api import run, env, cd

env.hosts = ['ubuntu@52.16.247.68']

def gitpull():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run('git pull')

def host_type():
    run('uname -s')

def start():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run('twistd -y rscserver.tac.py')

def stop():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run('kill `cat twistd.pid`')

def keys():
    with cd('/home/ubuntu/projects/rscoin/src'):
        run('python derivekey.py --store')
    
