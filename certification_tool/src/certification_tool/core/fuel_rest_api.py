import re
import json
import time
import urllib2
import pprint
from functools import partial, wraps
import netaddr


import type_check
from certification_script.cert_script import *


from keystoneclient.v2_0 import Client as keystoneclient
from keystoneclient import exceptions


logger = None


def set_logger(log):
    global logger
    logger = log


class Urllib2HTTP(object):
    """
    class for making HTTP requests
    """

    allowed_methods = ('get', 'put', 'post', 'delete', 'patch', 'head')

    def __init__(self, root_url, headers=None, echo=False):
        """
        """
        if root_url.endswith('/'):
            self.root_url = root_url[:-1]
        else:
            self.root_url = root_url

        self.headers = headers if headers is not None else {}
        self.echo = echo

    def do(self, method, path, params=None):
        if path.startswith('/'):
            url = self.root_url + path
        else:
            url = self.root_url + '/' + path

        if method == 'get':
            assert params == {} or params is None
            data_json = None
        else:
            data_json = json.dumps(params)

        if self.echo:
            logger.info("HTTP: {} {}".format(method.upper(), url))

        request = urllib2.Request(url,
                                  data=data_json,
                                  headers=self.headers)
        if data_json is not None:
            request.add_header('Content-Type', 'application/json')

        request.get_method = lambda: method.upper()
        response = urllib2.urlopen(request)

        if self.echo:
            logger.info("HTTP REsponce: {}".format(response.code))

        if response.code < 200 or response.code > 209:
            raise IndexError(url)

        content = response.read()

        if '' == content:
            return None

        return json.loads(content)

    def __getattr__(self, name):
        if name in self.allowed_methods:
            return partial(self.do, name)
        raise AttributeError(name)


class KeystoneAuth(Urllib2HTTP):
    def __init__(self, root_url, creds, headers=None, echo=False,
                 admin_node_ip=None):
        super(KeystoneAuth, self).__init__(root_url, headers, echo)
        self.keystone_url = "http://{0}:5000/v2.0".format(admin_node_ip)
        self.keystone = keystoneclient(
            auth_url=self.keystone_url, **creds)
        self.refresh_token()

    def refresh_token(self):
        """Get new token from keystone and update headers"""
        try:
            self.keystone.authenticate()
            self.headers['X-Auth-Token'] = self.keystone.auth_token
        except exceptions.AuthorizationFailure:
            logger.warning(
                'Cant establish connection to keystone with url %s',
                self.keystone_url)

    def do(self, method, path, params=None):
        """Do request. If gets 401 refresh token"""
        try:
            return super(KeystoneAuth, self).do(method, path, params)
        except urllib2.HTTPError as e:
            if e.code == 401:
                logger.warning('Authorization failure: {0}'.format(e.read()))
                self.refresh_token()
                return super(KeystoneAuth, self).do(method, path, params)
            else:
                raise


def get_inline_param_list(url):
    format_param_rr = re.compile(r"\{([a-zA-Z_]+)\}")
    for match in format_param_rr.finditer(url):
        yield match.group(1)


class RestObj(object):
    name = None
    id = None

    def __init__(self, conn, **kwargs):
        self.__dict__.update(kwargs)
        self.__connection__ = conn

    def __str__(self):
        res = ["{}({}):".format(self.__class__.__name__, self.name)]
        for k, v in sorted(self.__dict__.items()):
            if k.startswith('__') or k.endswith('__'):
                continue
            if k != 'name':
                res.append("    {}={!r}".format(k, v))
        return "\n".join(res)

    def __getitem__(self, item):
        return getattr(self, item)


def make_call(method, url):
    def closure(obj, entire_obj=None, **data):
        inline_params_vals = {}
        for name in get_inline_param_list(url):
            if name in data:
                inline_params_vals[name] = data[name]
                del data[name]
            else:
                inline_params_vals[name] = getattr(obj, name)
        result_url = url.format(**inline_params_vals)

        if entire_obj is not None:
            if data != {}:
                raise ValueError("Both entire_obj and data provided")
            data = entire_obj

        print result_url, data

        return obj.__connection__.do(method, result_url, params=data)
    return closure


PUT = partial(make_call, 'put')
GET = partial(make_call, 'get')
DELETE = partial(make_call, 'delete')


def with_timeout(tout, message):
    def closure(func):
        @wraps(func)
        def closure2(*dt, **mp):
            ctime = time.time()
            etime = ctime + tout

            while ctime < etime:
                if func(*dt, **mp):
                    return
                sleep_time = ctime + 1 - time.time()
                if sleep_time > 0:
                    time.sleep(sleep_time)
                ctime = time.time()
            raise RuntimeError("Timeout during " + message)
        return closure2
    return closure


# -------------------------------  ORM ----------------------------------------


def get_fuel_info(url):
    conn = Urllib2HTTP(url)
    return FuelInfo(conn)


class FuelInfo(RestObj):

    """Class represents Fuel installation info"""

    get_nodes = GET('api/nodes')
    get_clusters = GET('api/clusters')
    get_cluster = GET('api/clusters/{id}')

    @property
    def nodes(self):
        """Get all fuel nodes"""
        return NodeList([Node(self.__connection__, **node) for node
                         in self.get_nodes()])

    @property
    def free_nodes(self):
        """Get unallocated nodes"""
        return NodeList([Node(self.__connection__, **node) for node in
                         self.get_nodes() if not node['cluster']])

    @property
    def clusters(self):
        """List clusters in fuel"""
        return [Cluster(self.__connection__, **cluster) for cluster
                in self.get_clusters()]


def remap_saved_networks(mapping):
    # only for saved networks
    name_remapping = {'admin': 'fuelweb_admin'}
    new_assigment = {}
    for net in mapping['assigned_networks']:
        uname = name_remapping.get(net['name'], net['name'])
        net_role_desc = {'name': uname, 'id': network_ids[uname]}
        new_assigment.setdefault(net['dev'], []).append(net_role_desc)

    for interface in curr_net_roles:
        interface['assigned_networks'] = new_assigment[interface['name']]


class Node(RestObj):
    """Represents node in Fuel"""

    get_info = GET('/api/nodes/{id}')
    get_interfaces = GET('/api/nodes/{id}/interfaces')
    update_interfaces = PUT('/api/nodes/{id}/interfaces')

    def set_network_assigment(self, mapping):
        """Assings networks to interfaces
        :param mapping: list (dict) interfaces info
        """

        type_check.check({str: [str]}, mapping)

        curr_interfaces = self.get_interfaces()

        network_ids = {}
        for interface in curr_interfaces:
            for net in interface['assigned_networks']:
                network_ids[net['name']] = net['id']

        #transform mappings
        new_assigned_networks = {}

        for dev_name, networks in mapping.items():
            new_assigned_networks[dev_name] = []
            for net_name in networks:
                nnet = {'name': net_name, 'id': network_ids[net_name]}
                new_assigned_networks[dev_name].append(nnet)

        # update by ref
        for dev_descr in curr_interfaces:
            if dev_descr['name'] in new_assigned_networks:
                nass = new_assigned_networks[dev_descr['name']]
                dev_descr['assigned_networks'] = nass

        self.update_interfaces(curr_interfaces, id=self.id)

    def set_node_name(self, name):
        """Update node name"""
        self.__connection__.put('nodes', [{'id': self.id, 'name': name}])

    def get_network_data(self):
        """Returns node network data"""
        node_info = self.get_info()
        return node_info.get('network_data')

    def get_roles(self):
        """Get node roles

        Returns: (roles, pending_roles)
        """
        node_info = self.get_info()
        return node_info.get('roles'), node_info.get('pending_roles')

    def get_ip(self, network='public'):
        """Get node ip

        :param network: network to pick
        """
        nets = self.get_network_data()
        for net in nets:
            if net['name'] == network:
                iface_name = net['dev']
                for iface in self.get_info()['meta']['interfaces']:
                    if iface['name'] == iface_name:
                        try:
                            return iface['ip']
                        except KeyError:
                            return netaddr.IPNetwork(net['ip']).ip
        raise Exception('Network %s not found' % network)


class NodeList(list):
    """Class for filtering nodes through attributes"""
    allowed_roles = ['controller', 'compute', 'cinder', 'ceph-osd', 'mongo',
                     'zabbix-server']

    def __getattr__(self, name):
        if name in self.allowed_roles:
            return [node for node in self if name in node.roles]


class Cluster(RestObj):
    """Class represents Cluster in Fuel"""

    add_node_call = PUT('api/nodes')
    start_deploy = PUT('api/clusters/{id}/changes')
    get_status = GET('api/clusters/{id}')
    delete = DELETE('api/clusters/{id}')
    get_tasks_status = GET("api/tasks?tasks={id}")
    get_networks = GET('api/clusters/{id}/network_configuration/{net_provider}')
    configure_networks = PUT('api/clusters/{id}/network_configuration/{net_provider}')

    _get_nodes = GET('api/nodes?cluster_id={id}')

    def __init__(self, *dt, **mp):
        super(Cluster, self).__init__(*dt, **mp)
        self.nodes = NodeList()
        self.network_roles = {}

    def check_exists(self):
        """Check if cluster exists"""
        try:
            self.get_status()
            return True
        except urllib2.HTTPError as err:
            if err.code == 404:
                return False
            raise

    def get_nodes(self):
        for node_descr in self._get_nodes():
            yield Node(self.__connection__, **node_descr)

    def add_node(self, node, roles, interfaces=None):
        """Add node to cluster

        :param node: Node object
        :param roles: roles to assign
        :param interfaces: mapping iface name to networks
        """
        data = {}
        data['pending_roles'] = roles
        data['cluster_id'] = self.id
        data['id'] = node.id
        data['pending_addition'] = True
        logger.debug("Adding node %s to cluster..." % node.id)
        self.add_node_call([data])
        self.nodes.append(node)

        if interfaces is not None:
            networks = {}
            for iface_name, params in interfaces.items():
                networks[iface_name] = params['networks']

            node.set_network_assigment(networks)

    def wait_operational(self, timeout):
        """Wait until cluster status operational"""
        def wo():
            status = self.get_status()['status']
            if status == "error":
                raise Exception("Cluster deploy failed")
            return self.get_status()['status'] == 'operational'
        with_timeout(timeout, "deploy cluster")(wo)()

    def deploy(self, timeout):
        """Start deploy and wait until all tasks finished"""
        logger.debug("Starting deploy...")
        self.start_deploy()

        self.wait_operational(timeout)

        def all_tasks_finished_ok(obj):
            ok = True
            for task in obj.get_tasks_status():
                if task['status'] == 'error':
                    raise Exception('Task execution error')
                elif task['status'] != 'ready':
                    ok = False
            return ok

        wto = with_timeout(timeout, "wait deployment finished")
        wto(all_tasks_finished_ok)(self)

    def set_networks(self, net_descriptions):
        """Update cluster networking parameters"""
        configuration = self.get_networks()
        current_networks = configuration['networks']
        parameters = configuration['networking_parameters']

        if net_descriptions.get('networks'):
            # net_mapping = {}
            # for net_description in net_descriptions['networks']:
            #     print net_description + "!!!!!!!!111one"
            #     net_mapping[net_descriptions[net_description["name"]]] = net_descriptions
            net_mapping = net_descriptions['networks']

            print "!!!!!!!!!!!!!!!!!!"
            pprint.pprint(net_mapping)
            print "-" * 80

            for net in current_networks:
                net_desc = net_mapping.get(net['name'])
                if net_desc:
                    net.update(net_desc)

        if net_descriptions.get('networking_parameters'):
            parameters.update(net_descriptions['networking_parameters'])

        self.configure_networks(**configuration)


def reflect_cluster(conn, cluster_id):
    """Returns cluster object by id"""
    c = Cluster(conn, id=cluster_id)
    c.nodes = NodeList(list(c.get_nodes()))
    return c


def get_all_nodes(conn):
    """Get all nodes from Fuel"""
    for node_desc in conn.get('api/nodes'):
        yield Node(conn, **node_desc)


def get_all_clusters(conn):
    """Get all clusters"""
    for cluster_desc in conn.get('api/clusters'):
        yield Cluster(conn, **cluster_desc)


get_cluster_attributes = GET('api/clusters/{id}/attributes')


def get_cluster_id(name, conn):
    """Get cluster id by name"""
    for cluster in get_all_clusters(conn):
        if cluster.name == name:
            logger.info('cluster name is %s' % name)
            logger.info('cluster id is %s' % cluster.id)
            return cluster.id


update_cluster_attributes = PUT('api/clusters/{id}/attributes')


sections = {
    'sahara': 'additional_components',
    'murano': 'additional_components',
    'ceilometer': 'additional_components',
    'volumes_ceph': 'storage',
    'images_ceph': 'storage',
    'ephemeral_ceph': 'storage',
    'objects_ceph': 'storage',
    'osd_pool_size': 'storage',
    'volumes_lvm': 'storage',
    'volumes_vmdk': 'storage',
    'tenant': 'access',
    'password': 'access',
    'user': 'access',
    'vc_password': 'vcenter',
    'cluster': 'vcenter',
    'host_ip': 'vcenter',
    'vc_user': 'vcenter',
    'use_vcenter': 'vcenter',
}


def create_empty_cluster(conn, cluster_desc, debug_mode=False):
    """Create new cluster with configuration provided"""
    logger.info("Creating new cluster %s" % cluster_desc['name'])
    data = {}
    data['nodes'] = []
    data['tasks'] = []
    data['name'] = cluster_desc['name']
    data['release'] = cluster_desc['release']
    data['mode'] = cluster_desc.get('deployment_mode')
    data['net_provider'] = cluster_desc['settings'].get('net_provider')
    data['net_segment_type'] = cluster_desc['settings'].get('net_segment_type')

    params = conn.post(path='/api/clusters', params=data)
    cluster = Cluster(conn, **params)

    settings = cluster_desc['settings']
    attributes = get_cluster_attributes(cluster)

    ed_attrs = attributes['editable']
    for option, value in settings.items():
        if option in sections:
            attr_val_dict = ed_attrs[sections[option]][option]
            attr_val_dict['value'] = value

    ed_attrs['common']['debug']['value'] = debug_mode
    update_cluster_attributes(cluster, attributes)

    return cluster
