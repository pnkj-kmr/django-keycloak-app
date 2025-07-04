#

# podman system connection add 10.0.4.100 \
#   ssh://root@10.0.4.100/run/podman/podman.sock

# podman system connection add 10.0.4.100 \
#   ssh://root@10.0.4.100/run/user/$(ssh root@10.0.4.100 id -u)/podman/podman.sock


kc_dev:
	export KEYCLOAK_ADMIN=admin && \
	export KEYCLOAK_ADMIN_PASSWORD=admin && \
	./keycloak/bin/kc.sh start-dev


dj:
	/Users/pankaj/Workspace/github.com/django-keycloak-app/venv/bin/python manage.py runserver
