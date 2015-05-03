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
    [_, host] = env.host_string.split("@")
    with cd('/home/ubuntu/projects/rscoin/src'):
        result = run('python derivekey.py --store')
        [_, key] = result.strip().split()
        
        import sys
        sys.path += ["."]
        import rscoin
        from base64 import b64encode, b64decode

        kid = b64encode(rscoin.Key(b64decode(key)).id())
        print [kid, host, 8080]
    
