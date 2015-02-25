#!/usr/bin/env python2
import time
import logging
import itertools
import collections
from argparse import ArgumentParser


from certification_tool import fuel_rest_api


logger = logging.getLogger("certification")


def create_empty_cluster(conn, cluster_desc,
                         debug_mode=False,
                         use_ceph=False):
    """Create new cluster with configuration provided"""

    data = {}
    data['nodes'] = []
    data['tasks'] = []
    data['name'] = cluster_desc['name']
    data['release'] = cluster_desc['release']
    data['mode'] = cluster_desc.get('deployment_mode')

    net_prov = cluster_desc.get('net_provider')
    if net_prov == "neutron_vlan":
        data['net_provider'] = "neutron"
        data['net_segment_type'] = 'vlan'
    else:
        data['net_provider'] = net_prov

    params = conn.post(path='/api/clusters', params=data)
    cluster = fuel_rest_api.Cluster(conn, **params)

    attributes = cluster.get_attributes()

    ed_attrs = attributes['editable']

    ed_attrs['common']['libvirt_type']['value'] = \
        cluster_desc.get('libvirt_type', 'kvm')

    if use_ceph:
        opts = ['ephemeral_ceph', 'images_ceph', 'images_vcenter']
        opts += ['iser', 'objects_ceph', 'volumes_ceph']
        opts += ['volumes_lvm', 'volumes_vmdk']

        for name in opts:
            val = ed_attrs['storage'][name]
            if val['type'] == 'checkbox':
                is_ceph = ('images_ceph' == name)
                is_ceph = is_ceph or ('volumes_ceph' == name)

                if is_ceph:
                    val['value'] = True
                else:
                    val['value'] = False
    cluster.set_attributes(attributes)

    return cluster


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


NodeGroup = collections.namedtuple('Node', ['roles', 'num', 'num_modif'])
RawNodeInfo = collections.namedtuple('RawNodeInfo', ['cpu', 'disk', 'node'])


def match_nodes(conn, cluster, max_nodes=None):
    node_groups = []

    for node_group in cluster:
        rroles, rcount = node_group.split(",")

        rroles = rroles.strip()
        rcount = rcount.strip()

        roles = [role.strip() for role in rroles.split('+')]

        if rcount.endswith("+"):
            node_groups.append(NodeGroup(roles, int(rcount[:-1]), '+'))
        else:
            node_groups.append(NodeGroup(roles, int(rcount), None))

    min_nodes = sum(node_group.num for node_group in node_groups)

    if max_nodes is not None and max_nodes < min_nodes:
        templ = "max_nodes ({0!r}) < min_nodes ({1!r})"
        raise ValueError(templ.format(max_nodes, min_nodes))

    for node_group in node_groups:
        logger.info("Node : {0}".format(node_group))

    controller_only = sum(node_group.num for node_group in node_groups
                          if ['controller'] == node_group.roles)

    while True:
        raw_nodes = [raw_node for raw_node in fuel_rest_api.get_all_nodes(conn)
                     if raw_node.cluster is None]

        if len(raw_nodes) < min_nodes:
            templ = "Waiting till {0} nodes will be available"
            logger.info(templ.format(min_nodes))
            time.sleep(10)
            continue
        break

    if len(raw_nodes) <= 1:
        raise ValueError("Nodes amount should be not less, than 2")

    cpu_disk = []
    for raw_node in raw_nodes:
        info = raw_node.get_info()

        cpu_count = int(info['meta']['cpu']['real'])
        disk_size = 0

        for disk in info['meta']['disks']:
            disk_size += int(disk['size'])

        cpu_disk.append(RawNodeInfo(cpu_count, disk_size, raw_node))

    cpu_disk.sort()

    # least performant node - controllers
    for idx, node_info in enumerate(cpu_disk[:controller_only]):
        descr = {'roles': ["controller"],
                 'name': "controller_{0}".format(idx)}
        yield (descr, node_info.node)

    cpu_disk = cpu_disk[controller_only:]
    non_c_node_groups = [node_group for node_group in node_groups
                         if ['controller'] != node_group.roles]

    def make_name(group, idx):
        return "_".join(group.roles + [str(idx)])

    compute_nodes = [node_group for node_group in non_c_node_groups
                     if 'compute' in node_group.roles]
    idx = 0
    for node_group in compute_nodes:
        for _ in enumerate(range(node_group.num), idx):
            name = make_name(node_group, idx)
            descr = {'roles': node_group.roles,
                     'name': name}
            yield (descr, cpu_disk.pop().node)

    data_nodes = [node_group for node_group in non_c_node_groups
                  if 'compute' not in node_group.roles]

    idx = 0
    for node_group in data_nodes:
        for idx, _ in enumerate(range(node_group.num), idx):
            name = make_name(node_group, idx)
            descr = {'roles': node_group.roles,
                     'name': name}
            yield (descr, cpu_disk.pop().node)

    strechable_node_groups = [node_group for node_group in node_groups
                              if node_group.num_modif == '+']

    if len(strechable_node_groups) != 0:
        cycle_over = enumerate(itertools.cycle(strechable_node_groups),
                               min_nodes)

        nums = dict((id(node_group), node_group.num)
                    for node_group in strechable_node_groups)

        for selected_nodes, node_group in cycle_over:
            if cpu_disk == [] or selected_nodes == max_nodes:
                break

            name = make_name(node_group, nums[id(node_group)])
            nums[id(node_group)] += 1
            descr = {'roles': node_group.roles,
                     'name': name}
            yield (descr, cpu_disk.pop().node)


def str2ip_range(ip_str):
    ip1, ip2 = ip_str.split("-")
    return [ip1.strip(), ip2.strip()]


def get_net_cfg_ref(network_config, network_name):
    for net in network_config['networks']:
        if net['name'] == network_name:
            return net
    raise KeyError("Network {0!r} not found".format(network_name))


def set_networks_params(cluster, net_settings):
    configuration = cluster.get_networks()
    curr_config = configuration['networking_parameters']

    if 'floating' in net_settings:
        curr_config['floating_ranges'] = \
            [str2ip_range(net_settings['floating'])]

    fields = ['net_manager', 'net_l23_provider', 'vlan_range']

    for field in fields:
        if field in net_settings:
            curr_config[field] = net_settings[field]

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

    if 'storage' in net_settings:
        if 'vlan' in net_settings['storage']:
            net = get_net_cfg_ref(configuration, 'storage')
            net['vlan_start'] = net_settings['storage']['vlan']

    if 'management' in net_settings:
        if 'vlan' in net_settings['management']:
            net = get_net_cfg_ref(configuration, 'management')
            net['vlan_start'] = net_settings['management']['vlan']

    cluster.configure_networks(**configuration)


def create_cluster(conn, cluster):
    nodes_iter = match_nodes(conn, cluster['nodes'])

    use_ceph = False

    if 'nodes' in cluster:
        for node_group in cluster['nodes']:
            if 'ceph-osd' in node_group:
                use_ceph = True

    if cluster.get('storage_type', None) == 'ceph':
        use_ceph = True

    if use_ceph:
        logger.info("Will use ceph as storage")

    logger.info("Creating empty cluster")
    cluster_obj = create_empty_cluster(conn, cluster,
                                       use_ceph=use_ceph)

    try:
        if 'network' in cluster:
            logger.info("Setting network parameters")
            set_networks_params(cluster_obj, cluster['network'])

        for node_desc, node in nodes_iter:
            node.set_node_name(node_desc['name'])
            templ = "Adding node {0} with roles {1}"

            logger.info(templ.format(node.name, ",".join(node_desc['roles'])))

            cluster_obj.add_node(node, node_desc['roles'])
    except:
        cluster_obj.delete()
        raise

    return cluster_obj
