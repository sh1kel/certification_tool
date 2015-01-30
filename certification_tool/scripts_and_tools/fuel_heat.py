#!/usr/bin/env python2
import sys
import time

from argparse import ArgumentParser

import yaml
import logging

from certification_tool import fuel_rest_api
from certification_tool.main import login

fuel_rest_api.set_logger(logging.getLogger())
logging.getLogger().setLevel(logging.DEBUG)


def parse_command_line(argv):
    parser = ArgumentParser("usage: %prog [options]")

    parser.add_argument('-a', '--auth',
                        help='keystone credentials in format '
                             'tenant_name:username:password',
                        dest="auth", default='admin:admin:admin')

    parser.add_argument('-u', '--fuelurl', help="fuel rest url",
                        dest='fuelurl', required=True)

    parser.add_argument('config_file',
                        help='yaml configuration file',
                        metavar="CLUSTER_CONFIG")

    return parser.parse_args(argv)


def match_nodes(conn, cluster):
    controller_count = int(cluster['controller'])
    compute_nodes = int(cluster['compute'])
    cinder = int(cluster.get('cinder', 0))
    ceph_osd = int(cluster.get('ceph_osd', 0))

    min_nodes = ceph_osd + cinder + compute_nodes + controller_count

    while True:
        nodes = [node for node in fuel_rest_api.get_all_nodes(conn)
                 if node.cluster is None]

        if len(nodes) < min_nodes:
            time.sleep(10)
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

        for i, node in enumerate(nodes[:controller_count]):
            descr = {'roles': ["controller"],
                     'name': "controller_{}".format(i)}
            yield (descr, node)
        nodes = nodes[controller_count:]

        for i, node in enumerate(nodes[:cinder]):
            descr = {'roles': ["cinder"],
                     'name': "cinder_{}".format(i)}
            yield (descr, node)
        nodes = nodes[cinder:]

        for i, node in enumerate(nodes[:ceph_osd]):
            descr = {'roles': ["ceph-osd"],
                     'name': "ceph_{}".format(i)}
            yield (descr, node)
        nodes = nodes[ceph_osd:]

        for i, node in enumerate(nodes):
            descr = {'roles': ["compute"],
                     'name': "compute_{}".format(i)}
            yield (descr, node)

        break


def str2ip_range(ip_str):
    ip1, ip2 = ip_str.split("-")
    return [ip1.strip(), ip2.strip()]


def set_networks_params(cluster, net_settings):
    configuration = cluster.get_networks()
    curr_config = configuration['networking_parameters']

    if 'floating' in net_settings:
        curr_config['floating_ranges'] = \
            [str2ip_range(net_settings['floating'])]

    if 'public' in net_settings:
        pub_settings = net_settings['public']
        for net in configuration['networks']:
            if net['name'] == 'public':

                if 'ip_ranges' in pub_settings:
                    ip_range = str2ip_range(pub_settings['ip_ranges'])
                    net['ip_ranges'] = [ip_range]

                if 'cidr' in pub_settings:
                    net['cidr'] = pub_settings['cidr']

                if 'gateway' in pub_settings:
                    net['gateway'] = pub_settings['gateway']

    cluster.configure_networks(**configuration)


def create_cluster(conn, cluster):

    nodes_iter = match_nodes(conn, cluster['nodes'])

    cluster_obj = fuel_rest_api.create_empty_cluster(conn, cluster)

    if 'network' in cluster:
        set_networks_params(cluster_obj, cluster['network'])

    for node_desc, node in nodes_iter:
        node.set_node_name(node_desc['name'])
        cluster_obj.add_node(node, node_desc['roles'])


def main(argv):
    args = parse_command_line(argv)
    conn = login(args.fuelurl, args.auth)
    cluster = yaml.load(open(args.config_file).read())

    for cluster_obj in fuel_rest_api.get_all_clusters(conn):
        if cluster_obj.name == cluster['name']:
            cluster_obj.delete()
            wd = fuel_rest_api.with_timeout(60, "Wait cluster deleted")
            wd(lambda co: not co.check_exists())(cluster_obj)

    create_cluster(conn, cluster)

if __name__ == "__main__":
    exit(main(sys.argv[1:]))
