
from pprint import pprint

from kubernetes import client, config


def main():
    config.load_kube_config()

    api = client.CustomObjectsApi()

    # definition of custom resource
    test_resource = {
        "apiVersion": "stable.example.com/v1",
        "kind": "CronTab",
        "metadata": {"name": "test-crontab"},
        "spec": {"cronSpec": "* * * * */5", "image": "my-awesome-cron-image"},
    }

    # patch to update the `spec.cronSpec` field
    cronspec_patch = {
        "spec": {"cronSpec": "* * * * */15", "image": "my-awesome-cron-image"}
    }

    # patch to add the `metadata.labels` field
    metadata_label_patch = {
        "metadata": {
            "labels": {
                "foo": "bar",
            }
        }
    }

    # create a cluster scoped resource
    created_resource = api.create_cluster_custom_object(
        group="stable.example.com",
        version="v1",
        plural="crontabs",
        body=test_resource,
    )
    print("[INFO] Custom resource `test-crontab` created!\n")

    # get the cluster scoped resource
    resource = api.get_cluster_custom_object(
        group="stable.example.com",
        version="v1",
        name="test-crontab",
        plural="crontabs",
    )
    print("%s\t\t%s" % ("NAME", "CRON-SPEC"))
    print(
        "%s\t%s\n" %
        (resource["metadata"]["name"],
         resource["spec"]["cronSpec"]))

    # patch the `spec.cronSpec` field of the custom resource
    patched_resource = api.patch_cluster_custom_object(
        group="stable.example.com",
        version="v1",
        plural="crontabs",
        name="test-crontab",
        body=cronspec_patch,
    )
    print("[INFO] Custom resource `test-crontab` patched to update the cronSpec schedule!\n")
    print("%s\t\t%s" % ("NAME", "PATCHED-CRON-SPEC"))
    print(
        "%s\t%s\n" %
        (patched_resource["metadata"]["name"],
         patched_resource["spec"]["cronSpec"]))

    # patch the `metadata.labels` field of the custom resource
    patched_resource = api.patch_cluster_custom_object(
        group="stable.example.com",
        version="v1",
        plural="crontabs",
        name="test-crontab",
        body=metadata_label_patch,
    )
    print("[INFO] Custom resource `test-crontab` patched to apply new metadata labels!\n")
    print("%s\t\t%s" % ("NAME", "PATCHED_LABELS"))
    print(
        "%s\t%s\n" %
        (patched_resource["metadata"]["name"],
         patched_resource["metadata"]["labels"]))

    # delete the custom resource "test-crontab"
    api.delete_cluster_custom_object(
        group="stable.example.com",
        version="v1",
        name="test-crontab",
        plural="crontabs",
        body=client.V1DeleteOptions(),
    )
    print("[INFO] Custom resource `test-crontab` deleted!")


if __name__ == "__main__":
    main()
