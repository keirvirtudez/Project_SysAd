import os
from openstack import connection

# EXACT values from Ubuntu admin-openrc.sh + /v3
os.environ['OS_AUTH_URL'] = 'http://127.0.0.1:5000/v3 '
os.environ['OS_USERNAME'] = 'admin'
os.environ['OS_PASSWORD'] = 'G8E02A3dpg9mBpfeMh10bKS9FAhhCUVNulVgJdLa'
os.environ['OS_PROJECT_NAME'] = 'admin'
os.environ['OS_USER_DOMAIN_NAME'] = 'Default'
os.environ['OS_PROJECT_DOMAIN_NAME'] = 'Default'

print('Connecting to OpenStack...')
print(f"URL: {os.environ['OS_AUTH_URL']}")

try:
    conn = connection.Connection(
        auth_url=os.environ['OS_AUTH_URL'],
        username=os.environ['OS_USERNAME'],
        password=os.environ['OS_PASSWORD'],
        project_name=os.environ['OS_PROJECT_NAME'],
        user_domain_name=os.environ['OS_USER_DOMAIN_NAME'],
        project_domain_name=os.environ['OS_PROJECT_DOMAIN_NAME'],
        identity_api_version='3'
    )
    
    # Test connection by listing projects
    print('Connected!')
    print('Projects:')
    for proj in conn.identity.projects():
        print(f'  - {proj.name}')
        
    print('Users:')
    for user in conn.identity.users():
        print(f'  - {user.name}')
        
    print('SUCCESS!')

except Exception as e:
    print(f'Error: {e}')
