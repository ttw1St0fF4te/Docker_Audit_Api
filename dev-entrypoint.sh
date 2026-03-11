#!/bin/sh
set -eu

sh ./mvnw -q -DskipTests compile
sh ./mvnw -DskipTests spring-boot:run &
app_pid=$!

cleanup() {
	kill "$app_pid" 2>/dev/null || true
}

compile_if_needed() {
	state=$(
		find pom.xml src/main src/test -type f -exec stat -c '%n %Y' {} + 2>/dev/null | sort
	)

	if [ "$state" != "$last_state" ]; then
		if [ -n "$last_state" ] && ! sh ./mvnw -q -DskipTests compile; then
			echo "Compilation failed; waiting for the next change."
		fi
		last_state="$state"
	fi
}

trap cleanup INT TERM

last_state=""

while kill -0 "$app_pid" 2>/dev/null; do
	compile_if_needed
	sleep 1
done

wait "$app_pid"