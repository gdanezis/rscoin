import boto3
ec2 = boto3.resource('ec2')

instances = ec2.instances.filter()
for instance in instances:
    print(instance.id, instance.state["Name"], instance.public_dns_name)

if False:
	ids = [i.id for i in instances]
	try:
		ec2.instances.filter(InstanceIds=ids).stop()
		ec2.instances.filter(InstanceIds=ids).terminate()
	except Exception as e:
		print e

if False:
	print ec2.create_instances(
		ImageId='ami-178be960', 
		InstanceType='t2.micro',
		SecurityGroupIds= [ 'sg-ae5f0fcb' ],
		MinCount=1, 
		MaxCount=1 )