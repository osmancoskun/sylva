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

install_data('LICENSE', install_dir: get_option('datadir') / 'licenses/sylva')
install_data('README.md', install_dir: get_option('datadir') / 'doc/sylva')

test('packaging', python, args: [files('scripts/test_packaging.py')], timeout: 60)
