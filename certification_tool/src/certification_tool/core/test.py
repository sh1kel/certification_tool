from certification_script.fuel_rest_api import Urllib2HTTP, FuelInfo


URL = 'http://172.18.201.16:8000'


def get_fuel_info(url):
    conn = Urllib2HTTP(url)
    return FuelInfo(conn)

if __name__ == '__main__':
    fuel_info = get_fuel_info(URL)
    nodes = fuel_info.get_nodes()

    for n in fuel_info.nodes:
        print n.id
        print n.networks

    node = fuel_info.nodes[0]
    mapping = node.networks

    keys = mapping.keys()
    mapping[keys[0]], mapping[keys[1]] = mapping[keys[1]], mapping[keys[0]]

    node.set_networks(mapping)
