# SPDX-FileCopyrightText: Copyright (C) 2024 Marek Küthe <m.k@mk16.de>
#
# SPDX-License-Identifier: GPL-3.0-or-later

project(
    'crazytrace',
    'cpp',
    version: '1.0.3',
    license: ['GPL-3.0-or-later'],
    default_options: [
        'buildtype=release',
        'optimization=2',
        'warning_level=3',
        'werror=true',
        'cpp_std=gnu++26',
        'b_asneeded=true',
        'b_lto=true',
        'b_ndebug=if-release',
        'b_pie=true'
    ],
    meson_version: '>=1.5.0'
)

cpp_compiler = meson.get_compiler('cpp')

main_file = files('src/main.cpp')
sources = files(
    'src/capability_managment.cpp',
    'src/configuration.cpp',
    'src/crazytrace.cpp',
    'src/landlock.cpp',
    'src/loglevel.cpp',
    'src/postup_commands.cpp',
    'src/nodecontainer.cpp',
    'src/nodeinfo.cpp',
    'src/nodereply.cpp',
    'src/noderequest.cpp',
    'src/randomgenerator.cpp',
    'src/seccomp.cpp',
    'src/tun_tap.cpp'
)
headers = files(
    'src/capability_managment.hpp',
    'src/configuration.hpp',
    'src/crazytrace.hpp',
    'src/deviceclient.hpp',
    'src/landlock.hpp',
    'src/loglevel.hpp',
    'src/postup_commands.hpp',
    'src/nodecontainer.hpp',
    'src/nodeinfo.hpp',
    'src/nodereply.hpp',
    'src/noderequest.hpp',
    'src/randomgenerator.hpp',
    'src/seccomp.hpp',
    'src/tun_tap.hpp'
)
tests_sources = files(
    'tests/loglevel_test.cpp',
    'tests/nodecontainer_test.cpp',
    'tests/nodeinfo_test.cpp',
    'tests/nodeinfo_children_test.cpp',
    'tests/nodereply_test.cpp',
    'tests/noderequest_test.cpp',
    'tests/randomgenerator_test.cpp'
)
all_sources = main_file + sources + headers + tests_sources

if get_option('native')
    native_flags = ['-march=native', '-mtune=native']

    add_project_arguments(cpp_compiler.get_supported_arguments(native_flags), language: 'cpp')
endif

if not cpp_compiler.has_header('unistd.h') or \
   not cpp_compiler.has_function('dup', prefix: '#include <unistd.h>')
    error('crazytrace requires unistd.h and the dup function')
endif

libtuntap_dep = dependency('libtuntap', required: false, include_type: 'system')
if not libtuntap_dep.found()
    libtuntap_dep = cpp_compiler.find_library('libtuntap', has_headers: ['tuntap.h'], required: true)
endif

# Workaround for https://github.com/boostorg/process/issues/494#issuecomment-3392312248
boost_dep = dependency('boost', modules: ['log', 'process', 'filesystem'], required: false, include_type: 'system')
if not boost_dep.found()
    boost_dep = dependency('boost', modules: ['log'], include_type: 'system')
    add_project_arguments('-DBOOST_PROCESS_V1', language: 'cpp')
endif

libcapng_dep = dependency('libcap-ng', required: false)
if libcapng_dep.found()
    add_project_arguments('-DHAVE_LIBCAPNG', language: 'cpp')
endif

seccomp_dep = dependency('libseccomp', required: false)
if seccomp_dep.found() and cpp_compiler.has_header('sys/syscall.h')
    add_project_arguments('-DHAVE_SECCOMP', language: 'cpp')
endif

if cpp_compiler.has_header('linux/landlock.h')
    add_project_arguments('-DHAVE_LANDLOCK', language: 'cpp')
    if not cpp_compiler.has_function('landlock_create_ruleset', prefix: '#include <linux/landlock.h>')
        if not cpp_compiler.has_header('sys/syscall.h')
            error('No landlock_create_ruleset function, need sys/syscall.h header.')
        endif
        add_project_arguments('-DNO_LANDLOCK_CREATE_RULESET', language: 'cpp')
    endif
    if not cpp_compiler.has_function('landlock_add_rule', prefix: '#include <linux/landlock.h>')
        if not cpp_compiler.has_header('sys/syscall.h')
            error('No landlock_add_rule function, need sys/syscall.h header.')
        endif
        add_project_arguments('-DNO_LANDLOCK_ADD_RULE', language: 'cpp')
    endif
    if not cpp_compiler.has_function('landlock_restrict_self', prefix: '#include <linux/landlock.h>')
        if not cpp_compiler.has_header('sys/syscall.h')
            error('No landlock_restrict_self function, need sys/syscall.h header.')
        endif
        add_project_arguments('-DNO_LANDLOCK_RESTRICT_SELF', language: 'cpp')
    endif
    cpp_compiler.compiles('#include <linux/landlock.h>\nstruct landlock_ruleset_attr attr = {.handled_access_fs = 0, .handled_access_net = 0, .scoped = 0};', name: 'Landlock supports scoped access control', required: true)
endif

libtins_dep = dependency('libtins', include_type: 'system')
yamlcpp_dep = dependency('yaml-cpp', include_type: 'system')
gtest_dep = dependency('gtest', main: true, required: false, include_type: 'system')

cppcheck = find_program('cppcheck', required: false)
if cppcheck.found()
    run_target('cppcheck', command: [
        cppcheck,
        # Do not check external libraries
        '--suppress=*:*/tins/*',
        '--suppress=*:*/boost/*',
        '--suppress=*:*/gtest/*',

        # Problems with detecting system libraries
        '--suppress=missingIncludeSystem',
        '--suppress=unmatchedSuppression',

        '--enable=warning,style,information,missingInclude',
        '--error-exitcode=1',
        '--check-level=exhaustive',
        '--inline-suppr',
        '--project=' + join_paths(meson.current_build_dir(), 'compile_commands.json')
    ])
endif

infer = find_program('infer', required: false)
if infer.found()
    run_target('infer', command: [
        infer,
        '--compilation-database',
        join_paths(meson.current_build_dir(), 'compile_commands.json'),
        '--fail-on-issue'
    ])
endif

flawfinder = find_program('flawfinder', required: false)
if flawfinder.found()
    run_target('flawfinder', command: [
        flawfinder,
        '--error-level=0',
        all_sources
    ])
endif

lizard = find_program('lizard', required: false)
if lizard.found()
    run_target('lizard', command: [
        lizard,
        '--CCN', '15',
        '--length', '400',
        '--arguments', '10',
        all_sources
    ])
endif

reuse = find_program('reuse', required: false)
if reuse.found()
    run_target('reuse-annotate', command: [
        reuse,
        'annotate',
        '--copyright', 'Marek Küthe <m.k@mk16.de>',
        '--license', 'GPL-3.0-or-later',
        '--year', '2024',
        '--copyright-prefix', 'spdx-string-c',
        '--merge-copyrights',
        '--recursive',
        '--skip-unrecognised',
        meson.current_source_dir()
    ])
    run_target('reuse-download', command: [
        reuse,
        'download',
        '--all'
    ])
    run_target('reuse-lint', command: [
        reuse,
        'lint'
    ])
endif

if get_option('install_systemd_unit')
    install_data(
        'systemd/crazytrace@.service',
        install_dir: 'lib/systemd/system'
    )
endif

deps = [libtuntap_dep, boost_dep, libtins_dep, yamlcpp_dep, libcapng_dep, seccomp_dep]

if gtest_dep.found()
    gtest = executable('gtest', sources + tests_sources, dependencies: [gtest_dep] + deps, include_directories: ['src/'])
    test('gtest', gtest)
endif

executable(
    'crazytrace',
    sources + main_file,
    dependencies: deps,
    install : true
)
