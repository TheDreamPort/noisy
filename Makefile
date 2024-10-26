TARGET = 127.0.0.1
INSTALLATION_SCRIPT = install.yml
USER = sysadmin

install:
# to work on macOS
# brew install hudochenkov/sshpass/sshpass
	@echo 'installing on remote host'
	ansible-playbook $(INSTALLATION_SCRIPT) -i $(TARGET), -f 10 --ask-pass --ask-become-pass --extra-vars '{"user":"$(USER)"}'
