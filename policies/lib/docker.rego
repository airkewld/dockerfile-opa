package lib.docker

## Do Not store secrets in ENV variables
suspicious_env_keys = [
	"passwd",
	"password",
	"pass",
	"secret",
	"key",
	"access",
	"access_key",
	"accesskey",
	"api_key",
	"apikey",
	"priv_key",
	"privkey",
	"token",
	"tkn",
	"docker_auth",
]

## These image tags shouldn't be used
blacklisted_img_tags = ["latest"]

## Blacklist users
forbidden_users = ["root"]

## Blacklist UIDs
forbidden_uids = ["0"]

## Blacklist specific commands
blacklisted_cmds = [
	"sudo",
	"apk upgrade",
	"apt upgrade",
	"apt-get upgrade",
	"dist-upgrade",
	"yum upgrade",
	"dnf upgrade",
]

blacklisted_ports = ["22"]
