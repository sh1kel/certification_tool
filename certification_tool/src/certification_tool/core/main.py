import os.path
import logging.config
from argparse import ArgumentParser

import yaml

from certification_tool.core import fuel_rest_api
from certification_tool.core import cert_script as cs


import certification_tool
cert_dir = os.path.dirname(certification_tool.__file__)
DEFAULT_CONFIG_PATH = os.path.join(cert_dir, "configs", "config.yaml")


def parse_config(cfg_path):
    with open(cfg_path) as f:
        return yaml.load(f.read())


def parse_command_line():
    parser = ArgumentParser("usage: %prog [options] FUEL_URL")

    parser.add_argument('-p', '--password',
                        help='password for email', default=None)

    parser.add_argument('-c', '--config',
                        help='config file path', default=DEFAULT_CONFIG_PATH)

    parser.add_argument('fuelurl', help='fuel rest url', metavar="FUEL_URL")

    parser.add_argument('-d', '--deploy-only',
                        help='only deploy cluster',
                        metavar="CONFIG_FILE",
                        dest="deploy_only")

    parser.add_argument('-s', '--save-config',
                        help='save network configuration',
                        metavar='CLUSTER_NAME',
                        dest="save_config", default=None)

    parser.add_argument('-r', '--reuse-config',
                        help='reuse previously stored network configuration',
                        dest="reuse_config", action="store_true",
                        default=False)

    parser.add_argument('-a', '--auth',
                        help='keystone credentials in format '
                             'tenant_name:username:password',
                        dest="creds", default=None)

    parser.add_argument('--delete',
                        help='delete list of environments '
                             'separated by coma e.g'
                             'environment1,environment2.'
                             ' Use ALL to delete all',
                        dest='delete', default=None)

    parser.add_argument('-e', '--email',
                        help='email to send results. '
                             'If not provided the results'
                             'will not be sent',
                        dest='email', default=None)

    parser.add_argument('-q', '--quiet',
                        help="don't print results to console",
                        dest='quiet', default=False, action='store_true')

    return parser.parse_args()


def merge_config(config, command_line):
    config['fuelurl'] = command_line.fuelurl


def setup_logger(log_config_file):
    with open(log_config_file) as fd:
        cfg = yaml.load(fd)

    logging.config.dictConfig(cfg)

    cs.set_logger(logging.getLogger('clogger'))
    fuel_rest_api.set_logger(logging.getLogger('clogger'))


def deploy_single_cluster(args, clusters, conn, logger, auto_delete=True,
                          additional_cfg=None):
    cluster_name_or_file = args['deploy_only']

    file_exists = os.path.exists(cluster_name_or_file)
    if cluster_name_or_file.endswith('.yaml') and file_exists:
        try:
            cluster = yaml.load(open(cluster_name_or_file).read())
        except Exception:
            print "Failed to load cluster from {}".format(cluster_name_or_file)
            raise
    else:
        try:
            cluster = clusters[cluster_name_or_file]
        except KeyError:
            templ = "Error: No cluster with name {} found"
            logger.fatal(templ.format(cluster_name_or_file))
            return 1

    if auto_delete:
        cs.delete_if_exists(conn, cluster['name'])

    cs.deploy_cluster(conn, cluster, additional_cfg=additional_cfg)
    return 0


def run_tests(conn, config, clusters, saved_cfg, test_run_timeout, logger):
    results = []
    tests_cfg = config['tests']['tests']
    for _, test_cfg in tests_cfg.iteritems():
        cluster = clusters[test_cfg['cluster']]

        tests_to_run = test_cfg['suits']

        cont_man = cs.make_cluster(conn,
                                   cluster,
                                   auto_delete=True,
                                   additional_cfg=saved_cfg)

        with cont_man as cluster_id:
            results = cs.run_all_tests(conn,
                                       cluster_id,
                                       test_run_timeout,
                                       tests_to_run)

            for testset in results:
                results.extend(testset['tests'])

            failed_tests = [test for test in results
                            if test['status'] == 'failure']

            for test in failed_tests:
                logger.error(test['name'])
                logger.error(" " * 10 + 'Failure message: '
                             + test['message'])
    return results


def main():
    # prepare and config
    args = parse_command_line()

    config_dir = os.path.dirname(args.config)

    def to_abs_path(rel_path):
        return os.path.join(config_dir, rel_path)

    config = parse_config(args.config)
    merge_config(config, args)

    gui_cfg_fname = to_abs_path(config["gui_config_file"])

    logger_config_file = to_abs_path(config["log_settings"])
    setup_logger(logger_config_file)

    logger = logging.getLogger('clogger')
    if args.creds:
        admin_node_ip = config['fuelurl'].split('/')[-1].split(':')[0]
        username, password, tenant_name = args.creds.split(":")
        keyst_creds = {'username': username,
                       'password': password,
                       'tenant_name': tenant_name}
        conn = fuel_rest_api.KeystoneAuth(config['fuelurl'],
                                          creds=keyst_creds,
                                          echo=True,
                                          admin_node_ip=admin_node_ip)
    else:
        conn = fuel_rest_api.Urllib2HTTP(config['fuelurl'], echo=True)

    test_run_timeout = config.get('testrun_timeout', 3600)

    clusters_file_rel_path = config['tests']['clusters_directory']
    clusters_file_path = to_abs_path(clusters_file_rel_path)
    clusters = cs.load_all_clusters(clusters_file_path)

    print clusters_file_path, clusters.keys()

    clusters_to_delete = args.delete
    if clusters_to_delete:
        if clusters_to_delete == "ALL":
            cs.delete_all_clusters(conn)
        else:
            for cl_name in clusters_to_delete.split(','):
                cs.delete_if_exists(conn, cl_name)
        return

    saved_cfg = None
    if args.reuse_config is True:
        saved_cfg = cs.load_config(gui_cfg_fname)

    if args.deploy_only is not None:
        return deploy_single_cluster(args, clusters, conn, logger,
                                     additional_cfg=saved_cfg)

    save_cluster_name = args.save_config
    if save_cluster_name is not None:
        clusters = list(fuel_rest_api.get_all_clusters(conn))
        if save_cluster_name == "AUTO":
            if len(clusters) > 1:
                print "Can't select cluster - more then one available"
                return 1
            save_cluster_name = clusters[0].name

        for cluster in clusters:
            if cluster.name == save_cluster_name:
                cfg = cs.load_config_from_fuel(conn, cluster.id)
                cs.store_config(cfg, gui_cfg_fname)
        return 0

    results = run_tests(conn,
                        config,
                        clusters,
                        saved_cfg,
                        test_run_timeout,
                        logger)

    email_for_results = args.get("email")
    if email_for_results:
        cs.send_results(email_for_results, results)

    # if not args.quiet:
    #     print_results(results)

    return 0


if __name__ == "__main__":
    exit(main())
