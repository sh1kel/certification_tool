import sys
import time
import pprint
import os.path
import smtplib
import datetime
import contextlib
import subprocess
import logging.config
from argparse import ArgumentParser
from email.mime.text import MIMEText

import yaml

import certification_tool
from certification_tool import fuel_rest_api
from certification_tool import cert_heat


cert_dir = os.path.dirname(certification_tool.__file__)
DEFAULT_CONFIG_PATH = os.path.join(cert_dir, "configs", "config.yaml")


logger = logging.getLogger("validation")


def setup_logger(log_config_file, log_level):
    if log_config_file.endswith(".yaml"):
        with open(log_config_file) as fd:
            cfg = yaml.load(fd)

        if log_level is not None:
            if "root" in cfg:
                cfg['root']['level'] = log_level

            for logger_cfg in cfg['loggers'].values():
                logger_cfg['level'] = log_level

        logging.config.dictConfig(cfg)
    else:
        logging.config.fileConfig(log_config_file)

        if log_level is not None:
            logger.setLevel(log_level)


@contextlib.contextmanager
def log_error(action, types=(Exception,)):
    if not action.startswith("!"):
        logger.info("Starts : " + action)
    else:
        action = action[1:]

    try:
        yield
    except Exception as exc:
        if isinstance(exc, types) and not isinstance(exc, StopIteration):
            templ = "Error during {0} stage: {1}"
            logger.critical(templ.format(action, exc.message))
        raise


CMDS = ["lshw -xml",
        # "lspci -vv -k -nn -t",
        # "blockdev --report",
        # "lsblk -atmf",
        #"dmidecode"]
# CMDS = ["lscpu",
#         "lspci -vv -k -nn -t",
#         "blockdev --report",
#         "lsblk -atmf",
#         "dmidecode"]
SSH_OPTS = "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
ssh_cmd_templ = "ssh {ssh_opts} root@{ip} {cmd}"


def gather_hw_info_subprocess(nodes, splitter='!' * 60):
    res = []
    try:
        for node in nodes:
            res.append(splitter)
            res.append("Node: %s %s" % (node.ip, " ".join(node.roles)))
            ip = node.ip
            logger.info("Gathering HW info for " + str(ip))
            for cmd in CMDS:
                ssh_cmd = ssh_cmd_templ.format(ssh_opts=SSH_OPTS,
                                               ip=ip,
                                               cmd=cmd)
                res.append(splitter)
                res.append(cmd)
                res.append(splitter)
                p = subprocess.Popen(ssh_cmd, shell=True,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)
                res.append(p.stdout.read())
        return "\n".join(res)
    except Exception as exc:
        raise
        return "HW info gathering failed! Error: {0}".format(exc.message)


def run_all_ostf_tests(conn, cluster_id, timeout):
    testsets = conn.get('/ostf/testsets/{0}'.format(cluster_id))
    tests = [testset['id'] for testset in testsets]

    for test_name in tests:

        data = {'testset': test_name,
                'tests': [],
                'metadata': {'cluster_id': cluster_id}}

        run_id = conn.post('ostf/testruns', [data])[0]['id']

        def check_ready(run_id):
            status = conn.get('/ostf/testruns/{0}'.format(run_id))
            return status['status'] == 'finished'

        wt = fuel_rest_api.with_timeout(timeout,
                                        "run test " + test_name)
        wt(check_ready)(run_id)

        yield conn.get('/ostf/testruns/{0}'.format(run_id))


def match_nodes(conn, min_nodes):
    results = []

    while True:
        nodes = [node for node in fuel_rest_api.get_all_nodes(conn)
                 if node.cluster is None]

        if len(nodes) < min_nodes:
            templ = "Only {0} nodes available. {1} requires. Wait 60 sec"
            logger.info(templ.format(len(nodes), min_nodes))
            time.sleep(60)
            continue

        if len(nodes) < 1:
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


def make_user_to_setup_networks(url):
    print "\n" + "#" * 60 + "\n"
    print "Please go to %s and configure network parameters." % url
    print "Then input 'ready' to continue or 'exit' to break:",

    resp = raw_input()
    while resp != "ready" and resp != "exit":
        print "Please, type 'ready' or 'exit' :",
        try:
            resp = raw_input()
        except:
            print
            raise

    print "\n" + "#" * 60 + "\n"

    return resp == 'ready'


def deploy_cluster(conn, cluster_desc, deploy_timeout, min_nodes,
                   ignore_task_errors=False):

    msg_templ = "Waiting till at least {0} nodes became available"
    logger.info(msg_templ.format(min_nodes))

    cluster = cert_heat.create_cluster(conn, cluster_desc)

    url = "%s/#cluster/%s/nodes" % (conn.root_url, cluster.id)

    try:
        if not make_user_to_setup_networks(url):
            raise SystemExit()
    except:
        logger.info("Exiting. Removing cluster")
        cluster.delete()
        wd = fuel_rest_api.with_timeout(60, "Wait cluster deleted")
        wd(lambda co: not co.check_exists())(cluster)
        raise

    logger.info("Start deploing. This may takes a hours. " +
                "You may follow deployment process in FUEL UI " +
                "in you browser")

    cluster.deploy(deploy_timeout, ignore_task_errors=ignore_task_errors)
    return cluster


def delete_if_exists(conn, name):
    for cluster_obj in fuel_rest_api.get_all_clusters(conn):
        if cluster_obj.name == name:
            cluster_obj.delete()
            wd = fuel_rest_api.with_timeout(60, "Wait cluster deleted")
            wd(lambda co: not co.check_exists())(cluster_obj)


@contextlib.contextmanager
def make_cluster(conn, cluster_desc, deploy_timeout, min_nodes,
                 reuse_cluster_id=None, ignore_task_errors=False):
    if reuse_cluster_id is None:
        for cluster_obj in fuel_rest_api.get_all_clusters(conn):
            if cluster_obj.name == cluster_desc['name']:
                logger.info("Deleting old cluster.... this may takes a while")
                cluster_obj.delete()
                wd = fuel_rest_api.with_timeout(60, "Wait cluster deleted")
                wd(lambda co: not co.check_exists())(cluster_obj)
                break

        logger.info("Start deploying cluster")

        c = deploy_cluster(conn, cluster_desc, deploy_timeout, min_nodes,
                           ignore_task_errors=ignore_task_errors)

        with log_error("!Get list of nodes"):
            nodes = list(c.get_nodes())
            c.nodes = fuel_rest_api.NodeList(nodes)
    else:
        msg = "Will reuse existing cluster with id={0}"
        logger.info(msg.format(reuse_cluster_id))
        with log_error("Reflecting cluster {0}".format(reuse_cluster_id)):
            c = fuel_rest_api.reflect_cluster(conn, reuse_cluster_id)

    try:
        yield c
    finally:
        if reuse_cluster_id is None:
            with log_error("Starts dropping cluster"):
                c.delete()


def update_cluster(cluster, cfg):

    cfg_for_mac = dict((val['main_mac'], val)
                       for name, val in cfg['nodes'].items())

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

            templ = "update network settings for node {0}"
            with log_error(templ.format(node.name)):
                node.set_network_assigment(mapping)

    net_data = cfg['network_provider_configuration']

    with log_error("update cluster network settings"):
        cluster.set_networks(net_data)


def parse_config(cfg_path):
    if not os.path.isfile(cfg_path):
        logger.error("No such file {0!r}".format(cfg_path))
        exit(1)

    with log_error("reading config file {0!r}".format(cfg_path)):
        with open(cfg_path) as f:
            fc = f.read()

    with log_error("parsing config file"):
        return yaml.load(fc)


def parse_command_line(argv):
    parser = ArgumentParser("usage: %prog [options]")

    parser.add_argument('-c', '--config',
                        help='config file path', default=DEFAULT_CONFIG_PATH)

    parser.add_argument('-a', '--auth',
                        help='keystone credentials in format '
                             'username:password:tenant_name',
                        dest="creds", default="admin:admin:admin")

    parser.add_argument('--deploy-timeout',
                        help='deploy timeout in minutes',
                        default=120, type=int, dest='deploy_timeout')

    parser.add_argument('--min-nodes',
                        help='minimal required nodes amount',
                        default=1, type=int, dest="min_nodes")

    parser.add_argument('--distrib',
                        help='Linux distribution - ubuntu or centos',
                        default='ubuntu', choices=('ubuntu', 'centos'))

    parser.add_argument('--ignore-task-errors',
                        help='ignore task errors',
                        default=False, action="store_true")

    parser.add_argument('--hw-report-only',
                        help='Only generate hardware report',
                        default=True, action="store_true")

    ll = "CRITICAL ERROR WARNING INFO DEBUG NOTSET".split()
    parser.add_argument('--log-level',
                        help='loging level',
                        choices=ll, dest="log_level",
                        default=None)

    #parser.add_argument("--fuel-ssh-creds", help="Depricated")

    # sending mail is disabled for now
    # parser.add_argument('-p', '--password',
    #                     help='password for email', default=None)
    # parser.add_argument('-e', '--email',
    #                     help='email to send results. '
    #                          'If not provided the results'
    #                          'will not be sent',
    #                     dest='email', default=None)

    parser.add_argument('--reuse-cluster', type=int,
                        help="reuse existing cluster for tests",
                        metavar="CLUSTER_ID", default=None)

    parser.add_argument('-q', '--quiet',
                        help="don't print results to console",
                        dest='quiet', default=False, action='store_true')

    parser.add_argument('--save-report-to', default=None,
                        metavar="RESULT_FILE", help="save report to file")

    parser.add_argument('fuelurl', help='fuel rest url', nargs="?",
                        metavar="FUEL_URL", default="http://localhost:8000")

    return parser.parse_args(argv)


def run_tests(conn, config, test_run_timeout,
              deploy_timeout, min_nodes,
              reuse_cluster_id=None,
              ignore_task_errors=False,
              hw_report_only=False,
              distrib='ubuntu'):

    if hw_report_only and not reuse_cluster_id:
        nodes = fuel_rest_api.FuelInfo(conn).nodes
        hw_info = gather_hw_info_subprocess(nodes)
        return [], [], [hw_info]

    tests_results = []
    cdescr = config['cluster_desc'].copy()

    cdescr['release'] = '1' if distrib == 'centos' else '2'

    cont_man = make_cluster(conn, cdescr,
                            deploy_timeout, min_nodes,
                            reuse_cluster_id=reuse_cluster_id,
                            ignore_task_errors=ignore_task_errors)

    with cont_man as cluster:
        logger.info("Cluster ready!")

        if not hw_report_only:
            with log_error("Start tests"):
                results = run_all_ostf_tests(conn,
                                             cluster.id,
                                             test_run_timeout)

            for testset in results:
                tests_results.extend(testset['tests'])

            failed_tests = [test for test in results
                            if test['status'] == 'failure']

            if len(failed_tests) != 0:
                templ = "Tests finished. {0} test are done," + \
                        " {1} test are failed : {2}"

                names = [tests_results['name']
                         for tests_results in failed_tests]

                msg = templ.format(len(tests_results),
                                   len(failed_tests),
                                   ", ".join(names))
                logger.info(msg)
            else:
                logger.info("All tests passed successfully!")

            for test in failed_tests:
                logger.error(test['name'])
                logger.error(" " * 10 + 'Failure message: '
                             + test['message'])

        else:
            logger.info("Tests skipped")
            tests_results = []

        nodes_info = []
        for node in conn.get('/api/nodes'):
            if node['cluster'] == cluster.id:
                nodes_info.append(node)

        hw_info = []
        logger.info("Gathering hardware info")
        ips = []
        for node in cluster.get_nodes():
            ips.append(node.get_ip("fuelweb_admin"))

        hw_info.append(gather_hw_info_subprocess(cluster.get_nodes()))

    return tests_results, nodes_info, hw_info


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
   Mirantis Openstack hardware validation run results
-----------------------------------------------------------
Date: {date}
Test version: {version}
Fuel version: {f_ver}
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


def make_report(results, nodes_info, hw_info, conn):
    dt = datetime.datetime.now()
    fuel_info = fuel_rest_api.FuelInfo(conn)
    fuel_version_list = fuel_info.get_version()
    [str(fv) for fv in fuel_version_list]
    fuel_version_str = ".".join(fuel_version_list)
    report = header.format(date=dt.strftime("%d %b %Y %H:%M"),
                           version=certification_tool.__version__,
                           f_ver=fuel_version_str)

    failed = [res for res in results if res['status'] != 'success']
    success = [res for res in results if res['status'] == 'success']

    report += "\n"

    if len(failed) == 0:
        templ = "All {0} tests are passwed succesfully!\n"
        report += templ.format(len(results))
    elif 1 == len(failed):
        report += "1 test from {0} tests is failed!\n".format(len(failed),
                                                              len(results))
    else:
        report += "{0} tests from {1} are failed!\n".format(len(failed),
                                                            len(results))

    report += "\n"

    for test in failed:
        report += "{0} {1}\n".format(test['name'], test['status'].capitalize())

    if len(success) == 1:
        report += "1 test passed successfully\n"
    else:
        report += "{0} tests passed successfully\n".format(len(success))

    for test in success:
        report += "{0} {1}\n".format(test['name'], test['status'].capitalize())

    report += "\n"

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

        cpus_info_lines_count = {}

        for cpu in meta['cpu']['spec']:
            count = cpus_info_lines_count.get(cpu['model'], 0)
            cpus_info_lines_count[cpu['model']] = count + 1

        node_info['cpus_info'] = "\n".join(
            "    {0} x {1}".format(descr, count)
            for descr, count in cpus_info_lines_count.items())

        # -----------------------------------------------------------------------------------
        node_info['disks_count'] = len(meta['disks'])

        disks_info_lines = {}
        for disk in meta['disks']:
            sz_gib = int(disk['size']) / (1024 ** 3)
            ln = "{0} {1} {2} GiB".format(disk['name'], disk['model'], sz_gib)
            disks_info_lines[ln] = disks_info_lines.get(ln, 0) + 1

        itm = disks_info_lines.items()
        node_info['disks_info'] = "\n".join(
                                    "    {0} x {1}".format(descr, count)
                                    for descr, count in itm)

        # -----------------------------------------------------------------------------------
        node_info['interfaces_count'] = len(meta['interfaces'])

        net_info_lines = []
        for interface in meta['interfaces']:
            if interface['current_speed'] is not None:
                speed = interface['current_speed']
            else:
                speed = "Unknown"

            ln = "{0} {1} {2} MiB/s".format(interface['name'],
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
            cline = "{0} nodes with config :".format(amount)
        else:
            cline = "One node with config :"

        report += cline.center(REPORT_WITH)
        report += node_descr + "\n"

    hw_report = "\n\n".join(hw_info)

    return report, hw_report


def main(argv):
    # prepare and config
    args = parse_command_line(argv)

    config_dir = os.path.dirname(args.config)

    cluster_config = parse_config(args.config)

    log_sett_file = cluster_config["log_settings"]
    logger_config_file = os.path.join(config_dir, log_sett_file)
    setup_logger(logger_config_file, args.log_level)

    fuel_url = args.fuelurl.strip()
    if fuel_url.endswith("/"):
        fuel_url = fuel_url[:-1]

    if args.creds:
        with log_error("connecting and login into FUEL"):
            conn = login(fuel_url, args.creds)
    else:
        with log_error("connecting into FUEL"):
            conn = fuel_rest_api.Urllib2HTTP(fuel_url, echo=True)

    test_run_timeout = cluster_config.get('testrun_timeout', 3600)

    if not args.min_nodes >= 1:
        log_error("Min nodes should be more than 1")
        return 1

    res = run_tests(conn,
                    cluster_config,
                    test_run_timeout,
                    args.deploy_timeout * 60,
                    args.min_nodes, 
                    reuse_cluster_id=args.reuse_cluster,
                    ignore_task_errors=args.ignore_task_errors,
                    hw_report_only=args.hw_report_only,
                    distrib=args.distrib)

    results, nodes_info, hw_info = res

    results = list(results)
    # email_for_results = args.get("email")
    # if email_for_results:
    #    cs.send_results(email_for_results, results)

    # make and store report
    report, hw_report = make_report(results, nodes_info, hw_info, conn)

    if not args.quiet:
        print report

    if args.save_report_to is None:
        fname = "HW_validation_report_{0}.txt".format(time.time())
    else:
        fname = args.save_report_to

    with open(fname, "w") as fd:
        fd.write(report)
        fd.write(hw_report)

    logger.info("Report stored into " + fname)

    return 0


if __name__ == "__main__":
    exit(main(sys.argv[1:]))
