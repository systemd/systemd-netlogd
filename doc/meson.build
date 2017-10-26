sphinx_sources = [
        'conf.py',
        'index.rst']

man_pages = [
        'systemd-netlogd.1']

mandir1 = join_paths(get_option('mandir'), 'man1')

sphinx_build = find_program('sphinx-build-3', 'sphinx-build')

custom_target(
             'man',
              command : [sphinx_build,
                       '-b', 'man',
                        meson.current_source_dir(),
                        meson.current_build_dir()],
              input : sphinx_sources,
              output : man_pages,
              install : true,
              install_dir : '/usr/share/man/man1')
