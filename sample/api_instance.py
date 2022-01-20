from kubernetes import client, config


def main():
    config.load_kube_config()

    api_instance = client.CoreV1Api()

    body = {
        "metadata": {
            "labels": {
                "foo": "bar",
                "baz": None}
        }
    }

    # Listing the cluster nodes
    node_list = api_instance.list_node()

    print("%s\t\t%s" % ("NAME", "LABELS"))
    # Patching the node labels
    for node in node_list.items:
        api_response = api_instance.patch_node(node.metadata.name, body)
        print("%s\t%s" % (node.metadata.name, node.metadata.labels))


if __name__ == '__main__':
    main()
