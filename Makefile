.PHONY: all setup addresssanitizer leaksanitizer undefinedsanitizer clean compile coverage install debian check cppcheck flawfinder clangtidy test clangformat

all: setup compile

setup:
	test -d build || meson setup build

sanitizer:
	meson setup --reconfigure --debug -Db_sanitize=address,undefined build

native:
	meson setup --reconfigure -Dnative=true build

setupcoverage:
	meson setup --reconfigure -Db_coverage=true build

clean: setup
	meson compile --clean -C build

compile: setup
	meson compile -C build

coverage: setupcoverage test
	ninja -C build coverage

install: setup compile
	meson install -C build

debian:
	dpkg-buildpackage -b

check: flawfinder cppcheck scanbuild clangtidy

cppcheck: setup
	meson compile -C build cppcheck

infer: setup
	meson compile -C build infer

flawfinder: setup
	meson compile -C build flawfinder

clangtidy: setup
	ninja -C build clang-tidy

scanbuild: setup
	ninja -C build scan-build

test: setup
	meson test -C build

clangformat: setup
	ninja -C build clang-format
