from certification_script.certification_script.fuel_rest_api import Urllib2HTTP, FuelInfo, Cluster


def get_fuel_info(url):
    conn = Urllib2HTTP(url)
    return FuelInfo(conn)


def filter_by_role(role):
    return filter(lambda x: role in x.pending_roles, fuel_info.nodes)

URL = 'http://172.18.201.16:8000'

if __name__ == '__main__':
    #Creating fue_info object
    fuel_info = get_fuel_info(URL)

    print fuel_info.get_nodes()
    print fuel_info.free_nodes
    print fuel_info.clusters
    print fuel_info.nodes

    #print nodes with roles
    #print all computes
    print fuel_info.nodes.compute
    print filter_by_role('controller')

    #Cluster
    cluster_id = 29
    conn = Urllib2HTTP(URL + '/api/clusters/' + str(cluster_id))
    cluster = Cluster(conn)

    roles = ['compute', 'controller', 'cinder']

    for x in zip(fuel_info.nodes, roles):
        cluster.add_node(x[0], x[1])

    cluster.wait_operational()
    cluster.deploy()
    cluster.delete()

    

