.. SPDX-License-Identifier: GPL-2.0-only
.. Copyright (C) 2022 Red Hat, Inc.

====================
BPF_MAP_TYPE_DEVMAP
====================

.. note::
   - ``BPF_MAP_TYPE_DEVMAP`` was introduced in kernel version 4.14

``BPF_MAP_TYPE_DEVMAP`` is a BPF map, primarily useful for networking
applications, that uses a key to lookup a reference to a net_device. A
devmap uses integers as keys and net_devices as values. The user provides
key/ifindex pairs to update the map with new net_devices.

Usage
=====

.. c:function::
   long bpf_map_update_elem(struct bpf_map *map, const void *key, const void *value, u64 flags)

net_device entries can be added or updated using the ``bpf_map_update_elem()``
helper. This helper replaces existing elements atomically. The ``flags``
parameter can be used to control the update behaviour:

- ``BPF_ANY`` will create a new element or update an existing element
- ``BPF_NOEXIST`` will create a new element only if one did not already
  exist
- ``BPF_EXIST`` will update an existing element

``bpf_map_update_elem()`` returns 0 on success, or negative error in
case of failure.

.. c:function::
   void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)

net_device entries can be retrieved using the ``bpf_map_lookup_elem()``
helper. This helper returns a pointer to the value associated with
``key``, or ``NULL`` if no entry was found.

.. c:function::
   long bpf_map_delete_elem(struct bpf_map *map, const void *key)

net_device entries can be deleted using the ``bpf_map_delete_elem()``
helper. This helper will return 0 on success, or negative error in case
of failure.

Examples
========

Kernel BPF
----------

The following code snippet shows how to declare a BPF_MAP_TYPE_DEVMAP
called tx_port.

.. code-block:: c

    struct {
        __uint(type, BPF_MAP_TYPE_DEVMAP);
        __uint(key_size, sizeof(int));
        __uint(value_size, sizeof(int));
        __uint(max_entries, 256);
    } tx_port SEC(".maps");

The following code snippet shows a simple xdp_redirect_map program.

.. code-block:: c

    SEC("xdp_redirect_map")
    int xdp_redirect_map_func(struct xdp_md *ctx)
    {
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        int action = XDP_PASS;

        /* Should do some parsing to validate the packet
         * should be redirected.
         */

        action = bpf_redirect_map(&tx_port, 0, 0);

    out:
        return action;
    }

Userspace
---------

The following code snippet shows how to update a devmap called ``tx_port``.

.. code-block:: c

    int update_devmap(struct bpf_object *obj, int ifindex, int redirect_ifindex)
    {
        int key = 0;
        int map_fd;

        map_fd = bpf_object__find_map_fd_by_name(obj, "tx_port");
        if (map_fd < 0 ) {
            printf("bpf_object__find_map_fd_by_name failed\n");
            return 1;
        }

        /* Update the devmap at index 0 with the ifindex value of the interface
         * to redirect to.
         */
        bpf_map_update_elem(map_fd, &key, &redirect_ifindex, 0);
        printf("redirect from ifnum=%d to ifnum=%d\n", ifindex, redirect_ifindex);

        return 0;
    }

References
===========

- https://lwn.net/Articles/728146/
