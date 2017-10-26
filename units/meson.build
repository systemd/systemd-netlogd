systemd_netlogd_conf = configure_file(
                       input : 'systemd-netlogd.service.in',
                       output : 'systemd-netlogd.service',
                       configuration : substs)
                       install_data(systemd_netlogd_conf,
                       install_dir : get_option('sysconfdir'))
