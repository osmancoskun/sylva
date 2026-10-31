project('sylva',
  version: run_command('python3', 'scripts/package.py', 'version', check: true).stdout().strip(),
  meson_version: '>=1.3.0',
  license: 'GPL-3.0-only',
)

python = import('python').find_installation('python3')
go = find_program(get_option('go'))
build_version = get_option('release_version')
if build_version == ''
  build_version = meson.project_version()
endif
module_mode = get_option('offline') ? 'vendor' : 'readonly'

# Go owns its dependency graph, including embedded files. Calling its cached
# builder on each compile also notices new Go files without reconfiguring Meson.
foreach binary : ['sylva', 'sylvad']
  custom_target(binary,
    output: binary,
    command: [python, files('scripts/build_go.py'),
      '--go', go.full_path(), '--source', meson.project_source_root(),
      '--output', '@OUTPUT@', '--package', './cmd/' + binary,
      '--version', build_version, '--module-mode', module_mode],
    build_by_default: true,
    build_always_stale: true,
    install: true,
    install_dir: get_option('bindir'),
    install_mode: 'rwxr-xr-x',
  )
endforeach

unit_dir = get_option('systemd_unit_dir')
if unit_dir == ''
  unit_dir = get_option('prefix') / 'lib/systemd/system'
endif
sysusers_dir = get_option('sysusers_dir')
if sysusers_dir == ''
  sysusers_dir = get_option('prefix') / 'lib/sysusers.d'
endif
service_conf = configuration_data()
service_conf.set('BINDIR', get_option('prefix') / get_option('bindir'))
service_conf.set('SYSCONFDIR', get_option('prefix') / get_option('sysconfdir'))
configure_file(input: 'packaging/systemd/sylvad.service.in', output: 'sylvad.service',
  configuration: service_conf, install_dir: unit_dir)
install_data('packaging/systemd/sylva.sysusers', install_dir: sysusers_dir, rename: 'sylva.conf')
install_data('packaging/sylvad.conf', install_dir: get_option('sysconfdir') / 'sylva', install_mode: 'rw-r-----')
install_data('packaging/sylvad.env', install_dir: get_option('sysconfdir') / 'sysconfig', rename: 'sylvad', install_mode: 'rw-------')
install_emptydir(get_option('localstatedir') / 'lib/sylva', install_mode: 'rwx------')
install_data('LICENSE', install_dir: get_option('datadir') / 'licenses/sylva')
if import('fs').exists('THIRD_PARTY_LICENSES')
  install_data('THIRD_PARTY_LICENSES', install_dir: get_option('datadir') / 'licenses/sylva')
endif
install_data('README.md', 'docs/packaging.md', install_dir: get_option('datadir') / 'doc/sylva')

test('packaging', python, args: [files('scripts/test_packaging.py')], timeout: 60)
