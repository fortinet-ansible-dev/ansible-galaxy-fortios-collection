==============================
Fortinet.Fortios Release Notes
==============================

.. contents:: Topics


v2.1.2
======

Release Summary
---------------

patch release of 2.1.2

Bugfixes
--------

- Fix a regression bug caused by non-required attributes.
- Fix an intentional exception for listed options.

v2.1.1
======

Release Summary
---------------

patch release of 2.1.1

Bugfixes
--------

- Fix the KeyError caused by non-required multi-value attributes in an object.

v2.1.0
======

Release Summary
---------------

minor release of 2.1.0

Major Changes
-------------

- New module fortios_monitor_fact.
- Support Fortios 7.0.
- Support Log APIs.

Bugfixes
--------

- Disable check_mode feature from all global objects of configuration modules due to 'state' issue.
- Fix a bug in IP_PREFIX.match().
- Fix the issue that the ``server_type`` is not updated in ``fortios_system_central_management``.
- Fix the unexpected warning caused by optinal params in ``fortios_monitor_fact`` and ``fortios_monitor``.

v2.0.2
======

Release Summary
---------------

patch release of 2.0.2

Major Changes
-------------

- Improve ``fortios_configuration_fact`` to use multiple selectors concurrently.
- Support ``check_mode`` in all cofigurationAPI-based modules.
- Support filtering for fact gathering modules ``fortios_configuration_fact`` and ``fortios_monitor_fact``.
- Support moving policy in ``firewall_central_snat_map``.
- Unify schemas for monitor API.

Bugfixes
--------

- Fix the authorization fails at log in with username and password in FOS7.0.
- Github Issue 103
- Github Issue 105

v2.0.1
======

Minor Changes
-------------

- fixed pylint testing errors.

v2.0.0
======

Release Summary
---------------

The major breaking release of FOS 2.x collections.

Major Changes
-------------

- New module fortios_configuration_fact
- New module fortios_json_generic
- New module fortios_monitor
- New module fortios_monitor_fact

Breaking Changes / Porting Guide
--------------------------------

- Generic FortiOS Module - FOS module to issue generic request with Ansible.
- Support for FOS Monitor API - several modules are new for monitor API.
- Unified Collection - The fortios collection itself will be adapting any FOS platforms.

Removed Features (previously deprecated)
----------------------------------------

- Removed module fortios_facts
- Removed module fortios_registration_forticare
- Removed module fortios_registration_vdom
- Removed module fortios_system_config_backup_restore
- Removed module fortios_system_vmlicense

Bugfixes
--------

- Deprecated second-layer state module parameter
- enable_log - Explicit logging option.

Known Issues
------------

- Modules for monitor API are not versioned yet.
