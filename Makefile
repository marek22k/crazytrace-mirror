
setup:
	test -d build || meson setup src build

addresssanitizer: setup
	meson setup --reconfigure --debug -Db_sanitize=address src build

leaksanitizer: setup
	meson setup --reconfigure --debug -Db_sanitize=leak src build

undefinedsanitizer: setup
	meson setup --reconfigure --debug -Db_sanitize=leak src build

clean:
	meson compile --clean -C build

compile: setup
	meson compile -C build

install: setup compile
	meson install -C build

debian:
	cd deb && ./build.sh

check: cppcheck flawfinder

cppcheck: setup
	meson compile -C build cppcheck

flawfinder: setup
	meson compile -C build flawfinder
