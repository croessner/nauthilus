#!/bin/bash

HOST="https://login.example.test"
APIV1="$HOST/api/v1"
CURL="/usr/bin/curl"
JQ="/usr/bin/jq"

# HTTP Basic Auth
USER="-u nauthilus:SECRET"


function usage() {
        cat <<-EOB
$(basename "$0") command subcommand arg

        command: bruteforce
        subcommand: flush | list
        - flush:        Remove an IP address from one or all buckets
        - list:         List all IPs that have been detected as attackers

        command: cache
        - flush:        Remove one or all users from all positive and negative caches.

        arg:            Required argument for the command/subcommand. Mostly
                        a username, IP address and rule name or the wildcard '*'.

        help:           Print this help
EOB
}

COMMAND="$1"
SUBCOMMAND="$2"
ARG1="$3"
ARG2="$4"

case "$COMMAND" in
	bruteforce)
		case "$SUBCOMMAND" in
			flush)
				if [[ -z "$ARG1" && -z "$ARG2" ]]; then
					usage

					exit 1
				fi

				OPTION="DELETE"
				D="-d"
				DATA="{\"ip_address\": \"$ARG1\", \"rule_name\":  \"$ARG2\"}"
				;;
			list)
				OPTION="POST"
				D=""
				DATA=""
				;;
		esac
		;;
	cache)
		case "$SUBCOMMAND" in
			flush)
				if [[ -z "$ARG1" ]]; then
					usage

					exit 1
				fi

				OPTION="DELETE"
				D="-d"
				DATA="{\"user\": \"$ARG1\"}"
				;;
		esac
		;;
	*)
		usage

		exit 0
		;;
esac

echo "$(basename "$0") $COMMAND $SUBCOMMAND data=$DATA"

$CURL -s -X $OPTION "$USER" $D "$DATA" $APIV1/"$COMMAND"/"$SUBCOMMAND" | $JQ

exit 0

# vim: ts=4 sw=4
