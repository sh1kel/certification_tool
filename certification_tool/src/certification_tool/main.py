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
from certification_tool import fuel_rest_api

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
        nodes = [node for node in fuel_rest_api.get_all_nodes(conn)
                 if node.cluster is None]

        if len(nodes) < min_nodes:
            if logger is not None:
                templ = "Only {} nodes available. {} requires. Wait 60 sec"
                logger.info(templ.format(len(nodes), min_nodes))

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

    if logger is not None:
        logger.debug("Sending results by email...")

    server.sendmail(mail_config['mail_from'],
                    [mail_config['mail_to']],
                    msg.as_string())
    server.quit()


def deploy_cluster(conn, cluster_desc, deploy_timeout, min_nodes):

    if logger is not None:
        msg_templ = "Waiting till at least {} nodes became available"
        logger.info(msg_templ.format(min_nodes))

    for count, (node_desc, node) in enumerate(match_nodes(conn, min_nodes)):
        if 0 == count:
            if logger is not None:
                logger.info("All required nodes are detected")
                logger.info("Creating empty cluster")
            cluster = fuel_rest_api.create_empty_cluster(conn, cluster_desc)

        cluster.add_node(node, node_desc['roles'])

    if logger is not None:
        logger.info("successfully add {} nodes to cluster".format(count))

    url = "%s/#cluster/%s/nodes" % (conn.root_url, cluster.id)

    print "\n" + "#" * 60 + "\n"
    print "Please go to %s and configure network parameters." % url
    print "Then input 'ready' to continue :",

    resp = raw_input()
    while resp != "ready":
        print "Please, type 'ready' :",
        resp = raw_input()

    print

    if logger is not None:
        logger.info("Start deploing. This may takes a hours. " +
                    "You may follow deployment process in FUEL UI " +
                    "in you browser")

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
        if logger is not None:
            logger.info("Deleting old cluster.... this may takes a while")

        if cluster_obj.name == cluster_desc['name']:
            cluster_obj.delete()
            wd = fuel_rest_api.with_timeout(60, "Wait cluster deleted")
            wd(lambda co: not co.check_exists())(cluster_obj)

    if logger is not None:
        logger.info("Start deploying cluster")

    c = deploy_cluster(conn, cluster_desc, deploy_timeout, min_nodes)
    nodes = list(c.get_nodes())
    c.nodes = fuel_rest_api.NodeList(nodes)

    # c = fuel_rest_api.reflect_cluster(conn, 19)

    try:
        yield c
    finally:
        if logger is not None:
            logger.info("Start dropping cluster")
        c.delete()


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
                        default=2, type=int, dest="min_nodes")

    ll = "CRITICAL ERROR WARNING INFO DEBUG NOTSET".split()
    parser.add_argument('--log-level',
                        help='loging level',
                        choices=ll, dest="log_level",
                        default=None)

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


def setup_logger(log_config_file, log_level):
    with open(log_config_file) as fd:
        cfg = yaml.load(fd)

    if log_level is not None:
        if "root" in cfg:
            cfg['root']['level'] = log_level

        for logger_cfg in cfg['loggers'].values():
            logger_cfg['level'] = log_level

    logging.config.dictConfig(cfg)
    global logger
    logger = logging.getLogger('clogger')

    fuel_rest_api.set_logger(logging.getLogger('clogger'))


def run_tests(conn, config, test_run_timeout,
              deploy_timeout, min_nodes, logger):
    tests_results = []

    cont_man = make_cluster(conn, config['cluster_desc'],
                            deploy_timeout, min_nodes)

    with cont_man as cluster:
        if logger is not None:
            logger.info("Cluster ready! Start tests")

        results = run_all_ostf_tests(conn,
                                     cluster.id,
                                     test_run_timeout)

        for testset in results:
            tests_results.extend(testset['tests'])

        failed_tests = [test for test in results
                        if test['status'] == 'failure']

        if logger is not None:
            if len(failed_tests) != 0:
                templ = "Tests finished. {} test are done," + \
                        " {} test are failed : {}"

                names = [tests_results['name']
                         for tests_results in failed_tests]

                msg = templ.format(len(tests_results),
                                   len(failed_tests),
                                   ", ".join(names))
                logger.info(msg)

        if logger is not None:
            for test in failed_tests:
                logger.error(test['name'])
                logger.error(" " * 10 + 'Failure message: '
                             + test['message'])

        nodes_info = []
        for node in conn.get('/api/nodes'):
            if node['cluster'] == cluster.id:
                nodes_info.append(node)

    return tests_results, nodes_info


def login(fuel_url, creds):
    if fuel_url.endswith("/"):
        fuel_url = fuel_url[:-1]

    admin_node_ip = fuel_url.split('/')[-1].split(':')[0]
    username, password, tenant_name = creds.split(":")
    keyst_creds = {'username': username,
                   'password': password,
                   'tenant_name': tenant_name}
    return fuel_rest_api.KeystoneAuth(fuel_url,
                                      creds=keyst_creds,
                                      echo=True,
                                      admin_node_ip=admin_node_ip)


header = """
           MOS hardware sertification run results
-----------------------------------------------------------
Date: {date}
Test version: {version}
-----------------------------------------------------------
"""


node_descr_templ = """
#----------------------------------------------------------
roles: {roles}
OS: {os}
Kernel params: {kernel_params}

Manufacturer: {manufacturer}

Cpu count: {cpus_count}
{cpus_info}

RAM: {memory}

Disks: {disks_count}
{disks_info}

Interfaces: {interfaces_count}
{interfaces_info}

"""


REPORT_WITH = 60


def make_report(results, nodes_info):
    report = header.format(date=time.time(),
                           version=certification_tool.__version__)

    failed = [res for res in results if res['status'] != 'success']
    success = [res for res in results if res['status'] == 'success']

    report += "\n"

    if len(failed) == 0:
        report += "All {} tests passwed succesfully!\n".format(len(results))
    elif 1 == len(failed):
        report += "1 test from {} tests is failed!\n".format(len(failed),
                                                             len(results))
    else:
        report += "{} tests from {} tests are failed!\n".format(len(failed),
                                                                len(results))

    report += "\n"

    for test in failed:
        report += "{} {}\n".format(test['name'], test['status'].capitalize())

    if len(success) == 1:
        report += "1 test passed successfully\n"
    else:
        report += "{} tests passed successfully\n".format(len(success))

    for test in failed:
        report += "{} {}\n".format(test['name'], test['status'].capitalize())

    report += "\n"

    for test in failed:
        report += "{} {}\n".format(test['name'], test['status'].capitalize())

    report += "Hardware configuration".center(REPORT_WITH) + "\n\n"

    nodes_descrs = []

    for node in nodes_info:
        node_info = {}
        # node_info['name'] = ""
        node_info['roles'] = " ".join(node['roles'])
        node_info['os'] = node['os_platform']
        node_info['manufacturer'] = node['manufacturer']
        node_info['kernel_params'] = node['kernel_params']

        meta = node['meta']

        # -----------------------------------------------------------------------------------
        node_info['cpus_count'] = meta['cpu']['real']

        cpus_info_lines = []
        for cpu in meta['cpu']['spec']:
            cpus_info_lines.append(cpu['model'])

        node_info['cpus_info'] = "\n".join("    " + i for i in cpus_info_lines)

        # -----------------------------------------------------------------------------------
        node_info['disks_count'] = len(meta['disks'])

        disks_info_lines = []
        for disk in meta['disks']:
            sz_gib = int(disk['size']) / (1024 ** 3)
            ln = "{} {} {} GiB".format(disk['name'], disk['model'], sz_gib)
            disks_info_lines.append(ln)

        node_info['disks_info'] = "\n".join("    " + i
                                            for i in disks_info_lines)

        # -----------------------------------------------------------------------------------
        node_info['interfaces_count'] = len(meta['interfaces'])

        net_info_lines = []
        for interface in meta['interfaces']:
            if interface['current_speed'] is not None:
                speed = int(interface['current_speed']) / (1024 ** 2)
            else:
                speed = "Unknown"

            ln = "{} {} {} MiB/s".format(interface['name'],
                                         interface['state'],
                                         speed)
            net_info_lines.append(ln)

        node_info['interfaces_info'] = "\n".join("    " + i
                                                 for i in net_info_lines)

        # -----------------------------------------------------------------------------------

        memory_count = 0
        for mem_dev in meta['memory']['devices']:
            memory_count += int(mem_dev['size']) / 1024 ** 2

        node_info['memory'] = str(memory_count) + " MiB"
        # -----------------------------------------------------------------------------------

        nodes_descrs.append(node_descr_templ.format(**node_info))

    for node_descr in set(nodes_descrs):
        amount = nodes_descrs.count(node_descr)

        if amount > 1:
            cline = "{} nodes with config :".format(amount)
        else:
            cline = "One node with config :"

        report += cline.center(REPORT_WITH)
        report += node_descr + "\n"

    return report


def main(argv):
    # prepare and config
    args = parse_command_line(argv)

    config_dir = os.path.dirname(args.config)

    config = parse_config(args.config)
    merge_config(config, args)

    logger_config_file = os.path.join(config_dir, (config["log_settings"]))
    setup_logger(logger_config_file, args.log_level)

    logger = logging.getLogger('clogger')

    fuel_url = config['fuelurl'].strip()
    if fuel_url.endswith("/"):
        fuel_url = fuel_url[:-1]

    if logger is not None:
        logger.info("Connecting to FUEL")

    if args.creds:
        conn = login(fuel_url, args.creds)
    else:
        conn = fuel_rest_api.Urllib2HTTP(fuel_url, echo=True)

    test_run_timeout = config.get('testrun_timeout', 3600)

    results, nodes_info = run_tests(conn,
                                    config,
                                    test_run_timeout,
                                    args.deploy_timeout * 60,
                                    args.min_nodes,
                                    logger)

    results = list(results)
    # email_for_results = args.get("email")
    # if email_for_results:
    #    cs.send_results(email_for_results, results)

    # import IPython
    # IPython.embed()

    report = make_report(results, nodes_info)
    if not args.quiet:
        print report

    fname = "HW_cert_report_{}.txt".format(time.time())
    with open(fname, "w") as fd:
        fd.write(report)

    logger.info("Report stored into " + fname)

    return 0


if __name__ == "__main__":
    exit(main(sys.argv[1:]))
