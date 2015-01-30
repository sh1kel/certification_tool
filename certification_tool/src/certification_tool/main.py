import sys
import time
import os.path
import smtplib
import contextlib
import logging.config
from argparse import ArgumentParser
from email.mime.text import MIMEText

import yaml

import certification_tool
fuel_rest_api = certification_tool.fuel_rest_api

cert_dir = os.path.dirname(certification_tool.__file__)
DEFAULT_CONFIG_PATH = os.path.join(cert_dir, "configs", "config.yaml")


logger = None


def run_all_ostf_tests(conn, cluster_id, timeout):
    testsets = conn.get('/ostf/testsets/{}'.format(cluster_id))
    tests = [testset['id'] for testset in testsets]

    for test_name in tests:

        data = {'testset': test_name,
                'tests': [],
                'metadata': {'cluster_id': cluster_id}}

        run_id = conn.post('ostf/testruns', [data])[0]['id']

        def check_ready(run_id):
            status = conn.get('/ostf/testruns/{}'.format(run_id))
            return status['status'] == 'finished'

        wt = fuel_rest_api.with_timeout(timeout,
                                        "run test " + test_name)
        wt(check_ready)(run_id)

        yield conn.get('/ostf/testruns/{}'.format(run_id))


def match_nodes(conn, min_nodes):
    results = []

    while True:
        nodes = list(fuel_rest_api.get_all_nodes(conn))

        if len(nodes) < min_nodes:
            time.sleep(60)
            continue

        if len(nodes) <= 1:
            raise ValueError("Nodes amount should be not less, than 2")

        cpu_disk = []
        for node in nodes:
            info = node.get_info()

            cpu_count = int(info['meta']['cpu']['real'])
            disk_size = 0

            for disk in info['meta']['disks']:
                disk_size += int(disk['size'])

            cpu_disk.append((disk_size, cpu_count, node))

        cpu_disk.sort()
        nodes = [tpl[2] for tpl in cpu_disk]

        results.append(({'roles': ["controller"]}, nodes[0]))

        nodes = nodes[1:]

        num_computes = max(1, int((len(nodes) + 1) / 2))

        for node in nodes[:num_computes]:
            results.append(({'roles': ["compute"]}, node))

        for node in nodes[num_computes:]:
            results.append(({'roles': ["cinder"]}, node))

        break

    return results


def send_results(mail_config, tests):
    server = smtplib.SMTP(mail_config['smtp_server'], 587)
    server.starttls()
    server.login(mail_config['login'], mail_config['password'])

    # Form message body
    failed_tests = [test for test in tests if test['status'] == 'failure']
    msg = '\n'.join([test['name'] + '\n        ' + test['message']
                     for test in failed_tests])

    msg = MIMEText(msg)
    msg['Subject'] = 'Test Results'
    msg['To'] = mail_config['mail_to']
    msg['From'] = mail_config['mail_from']

    logger.debug("Sending results by email...")
    server.sendmail(mail_config['mail_from'],
                    [mail_config['mail_to']],
                    msg.as_string())
    server.quit()


def deploy_cluster(conn, cluster_desc, deploy_timeout, min_nodes):

    cluster = fuel_rest_api.create_empty_cluster(conn, cluster_desc)

    for node_desc, node in match_nodes(conn, min_nodes):
        cluster.add_node(node, node_desc['roles'])

    url = "%s/#cluster/%s/nodes" % (conn.root_url, cluster.id)

    print "\n\n" + "#" * 60
    print "Please go to %s and configure nodes interfaces." % url + \
          "Then input 'ready' to continue :",

    resp = raw_input()
    while resp != "ready":
        print "Please, type 'ready' :",
        resp = raw_input()

    cluster.deploy(deploy_timeout)
    return cluster


def delete_if_exists(conn, name):
    for cluster_obj in fuel_rest_api.get_all_clusters(conn):
        if cluster_obj.name == name:
            cluster_obj.delete()
            wd = fuel_rest_api.with_timeout(60, "Wait cluster deleted")
            wd(lambda co: not co.check_exists())(cluster_obj)


@contextlib.contextmanager
def make_cluster(conn, cluster_desc, deploy_timeout, min_nodes):
    for cluster_obj in fuel_rest_api.get_all_clusters(conn):
        if cluster_obj.name == cluster_desc['name']:
            cluster_obj.delete()
            wd = fuel_rest_api.with_timeout(60, "Wait cluster deleted")
            wd(lambda co: not co.check_exists())(cluster_obj)

    c = deploy_cluster(conn, cluster_desc, deploy_timeout, min_nodes)

    nodes = list(c.get_nodes())
    c.nodes = fuel_rest_api.NodeList(nodes)

    try:
        yield c
    finally:
        # c.delete()
        pass


def update_cluster(cluster, cfg):

    cfg_for_mac = {val['main_mac']: val for name, val in cfg['nodes'].items()}

    for node in cluster.get_nodes():
        if node.mac in cfg_for_mac:
            node_cfg = cfg_for_mac[node.mac]

            mapping = {}
            for net_descr in node_cfg['network_data']:
                net_name = net_descr['name']
                if net_name == 'admin':
                    net_name = 'fuelweb_admin'
                dev_name = net_descr['dev']
                mapping.setdefault(dev_name, []).append(net_name)

            node.set_network_assigment(mapping)

    net_data = cfg['network_provider_configuration']
    cluster.set_networks(net_data)


def parse_config(cfg_path):
    with open(cfg_path) as f:
        return yaml.load(f.read())


def parse_command_line(argv):
    parser = ArgumentParser("usage: %prog [options]")

    parser.add_argument('-c', '--config',
                        help='config file path', default=DEFAULT_CONFIG_PATH)

    parser.add_argument('-a', '--auth',
                        help='keystone credentials in format '
                             'tenant_name:username:password',
                        dest="creds", default=None)

    parser.add_argument('--deploy-timeout',
                        help='deploy timeout in minutes',
                        default=120, type=int, dest='deploy_timeout')

    parser.add_argument('--min-nodes',
                        help='minimal required nodes amount',
                        default=None, type=int, dest="min_nodes")

    # sending mail is disabled for now
    # parser.add_argument('-p', '--password',
    #                     help='password for email', default=None)
    # parser.add_argument('-e', '--email',
    #                     help='email to send results. '
    #                          'If not provided the results'
    #                          'will not be sent',
    #                     dest='email', default=None)

    parser.add_argument('-q', '--quiet',
                        help="don't print results to console",
                        dest='quiet', default=False, action='store_true')

    parser.add_argument('fuelurl', help='fuel rest url', metavar="FUEL_URL")

    return parser.parse_args(argv)


def merge_config(config, command_line):
    config['fuelurl'] = command_line.fuelurl


def setup_logger(log_config_file):
    with open(log_config_file) as fd:
        cfg = yaml.load(fd)

    logging.config.dictConfig(cfg)

    fuel_rest_api.set_logger(logging.getLogger('clogger'))


def run_tests(conn, config, test_run_timeout,
              deploy_timeout, min_nodes, logger):
    tests_results = []

    # cont_man = make_cluster(conn, config['cluster_desc'],
    #                         deploy_timeout, min_nodes)

    # with cont_man as cluster:

    cluster = fuel_rest_api.reflect_cluster(conn, 8)

    results = run_all_ostf_tests(conn,
                                 cluster.id,
                                 test_run_timeout)

    for testset in results:
        tests_results.extend(testset['tests'])

    failed_tests = [test for test in results
                    if test['status'] == 'failure']

    for test in failed_tests:
        logger.error(test['name'])
        logger.error(" " * 10 + 'Failure message: '
                     + test['message'])

    return tests_results


def main(argv):
    # prepare and config
    args = parse_command_line(argv)

    config_dir = os.path.dirname(args.config)

    config = parse_config(args.config)
    merge_config(config, args)

    logger_config_file = os.path.join(config_dir, (config["log_settings"]))
    setup_logger(logger_config_file)

    logger = logging.getLogger('clogger')

    fuel_url = config['fuelurl'].strip()
    if fuel_url.endswith("/"):
        fuel_url = fuel_url[:-1]

    if args.creds:
        admin_node_ip = fuel_url.split('/')[-1].split(':')[0]
        username, password, tenant_name = args.creds.split(":")
        keyst_creds = {'username': username,
                       'password': password,
                       'tenant_name': tenant_name}
        conn = fuel_rest_api.KeystoneAuth(fuel_url,
                                          creds=keyst_creds,
                                          echo=True,
                                          admin_node_ip=admin_node_ip)
    else:
        conn = fuel_rest_api.Urllib2HTTP(fuel_url, echo=True)

    test_run_timeout = config.get('testrun_timeout', 3600)

    results = run_tests(conn,
                        config,
                        test_run_timeout,
                        args.deploy_timeout * 60,
                        args.min_nodes,
                        logger)

    results = list(results)
    # email_for_results = args.get("email")
    # if email_for_results:
    #    cs.send_results(email_for_results, results)

    nodes_info = conn.get('/api/nodes')

    if not args.quiet:
        print results
        print nodes_info

    return 0


if __name__ == "__main__":
    exit(main(sys.argv[1:]))
