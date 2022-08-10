package docker

import data.lib.docker

## Looking for suspicious environment variables
# ENV should be set one per directive
# ENV HOME="/"
# ENV PASS="pass"

deny_suspicious_env[msg] {
	input[i].Cmd == "env"
	val := input[i].Value
	contains(docker.suspicious_env_keys[_], lower(val[_]))
	msg = sprintf("Potential secret in ENV key found: %s", [val[0]])
}

## Do not use 'latest' tag for base image
warn_latest_tag[msg] {
	input[i].Cmd == "from"
	val := split(input[i].Value[0], ":")
	contains(docker.blacklisted_img_tags[_], lower(val[1]))
	msg = sprintf("Do not use 'latest' tag for base images %s", [val])
}

## Empty tag is the same as 'latest' tag
warn_latest_tag[msg] {
	input[i].Cmd == "from"
	val := split(input[i].Value[0], ":")
	not val[1]
	msg = sprintf("Please include a tag for the base image, otherwise you run the risk of running latest %s", [val])
}

## Require USER
any_user {
	input[i].Cmd == "user"
}

deny_missing_user[msg] {
	not any_user
	msg = "Do not run as root, use USER instead."
}

deny_forbidden_users[msg] {
	command := "user"
	users := [name | input[i].Cmd == command; name := input[i].Value]
	lastuser := users[count(users)-1]
	contains(docker.forbidden_users[_], lower(lastuser[_]))
	msg = sprintf("Last USER directive defined as %s is forbidden", [lastuser])
}

deny_forbidden_uid[msg] {
	command := "user"
	users := [uid | input[i].Cmd == command; uid := input[i].Value]
	lastuser := users[count(users)-1]
	contains(docker.forbidden_uids[_], lower(lastuser[_]))
	msg = sprintf("Last USER directive defined as %s is forbidden", [lastuser])
}

## Blacklist specific commands
deny_blacklisted_commands[msg] {
	input[i].Cmd == "run"
	val := concat(" ", input[i].Value)
	contains(docker.blacklisted_cmds[_], lower(val))
	msg = sprintf("Command '%s' is forbidden", [val])
}

## Use COPY instead of ADD
warn_use_copy[msg] {
	input[i].Cmd == "add"
	val := concat(" ", input[i].Value)
	msg = sprintf("Use COPY instead of ADD: %s", [val])
}

## No Healthcheck defined
health_check {
	input[i].Cmd == "healthcheck"
}

warn_healthcheck[msg] {
	not health_check
	msg = "Missing HEALTHCHECK."
}

## Blacklist exposed ports
deny_blacklisted_ports[msg] {
	input[i].Cmd == "expose"
	val := input[i].Value
	contains(docker.blacklisted_ports[_], val[_])
	msg = sprintf("Port %s can't be exposed", [val])
}

exception[rules] {
	input[i].Cmd == "label"
	input[i].Value[0] == "whitelist"
	input[i].Value[1] == "can-run-as-root"

	rules := [
		"missing_user",
		"forbidden_user",
		"forbidden_uid",
	]
}
