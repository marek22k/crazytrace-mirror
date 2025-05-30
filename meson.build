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
        'cpp_std=c++20',
        'b_asneeded=true',
        'b_lto=true',
        'b_ndebug=if-release',
        'b_pie=true'
    ]
)

cpp_compiler = meson.get_compiler('cpp')

main_file = files('src/main.cpp')
sources = files(
    'src/configuration.cpp',
    'src/crazytrace.cpp',
    'src/loglevel.cpp',
    'src/postup_commands.cpp',
    'src/nodecontainer.cpp',
    'src/nodeinfo.cpp',
    'src/nodereply.cpp',
    'src/noderequest.cpp',
    'src/randomgenerator.cpp',
    'src/tun_tap.cpp'
)
headers = files(
    'src/configuration.hpp',
    'src/crazytrace.hpp',
    'src/deviceclient.hpp',
    'src/loglevel.hpp',
    'src/postup_commands.hpp',
    'src/nodecontainer.hpp',
    'src/nodeinfo.hpp',
    'src/nodereply.hpp',
    'src/noderequest.hpp',
    'src/randomgenerator.hpp',
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

boost_dep = dependency('boost', modules: ['log'], include_type: 'system')
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
        # '--check-level=exhaustive', - not yet in debian
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
        sources + tests_sources + headers
    ])
endif

lizard = find_program('lizard', required: false)
if lizard.found()
    run_target('lizard', command: [
        lizard,
        '--CCN', '15',
        '--length', '400',
        '--arguments', '10',
        sources + tests_sources + headers
    ])
endif

if get_option('install_systemd_unit')
    install_data(
        'systemd/crazytrace@.service',
        install_dir: 'lib/systemd/system'
    )
endif

deps = [libtuntap_dep, boost_dep, libtins_dep, yamlcpp_dep]

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
