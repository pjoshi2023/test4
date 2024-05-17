OIDC Claims Support Authenticator Plug-in
===========================================

.. image:: https://travis-ci.org/curityio/oidc-claims-support-authenticator.svg?branch=dev
     :target: https://travis-ci.org/curityio/oidc-claims-support-authenticator

This project provides an Authenticator plug-in for the Curity Identity Server. The plugin is a basic authenticator using an OIDC provider for authentication. This plugin support the request of claims using claims request parameter.

.. note::
    This authenticator does not implement its own client authentication, meaning that the configured HTTP client must have the Basic authentication scheme enabled, and the provider must support Basic authentication for the token request.


System Requirements
~~~~~~~~~~~~~~~~~~~

* Curity Identity Server 8.6.0 and `its system requirements <https://curity.io/docs/idsvr/latest/system-admin-guide/system-requirements.html>`_ (Older versions may be supported if the SDK version is changed in the pom.xml)

Requirements for Building from Source
"""""""""""""""""""""""""""""""""""""

* Java JDK v. 8

Compiling the Plug-in from Source
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The source is very easy to compile. To do so from a shell, issue this command: ``./gradlew build``. The result will be the plugin jar in the `build/libs` folder. Next gather the jar ``oidc-claims-support-1.0.0-SNAPSHOT.jar``

Installation
~~~~~~~~~~~~

To install this plug-in, compile it from source (as described above). The resulting JAR file as well as the dependencies needs to placed in the directory ``${IDSVR_HOME}/usr/share/plugins/oidc-claims-support``. (The name of the last directory, ``oidc-claims-support``, which is the plug-in group, is arbitrary and can be anything.) After doing so, the plug-in will become available as soon as the node is restarted.

.. note::

    The JAR file needs to be deployed to each run-time node and the admin node. For simple test deployments where the admin node is a run-time node, the JAR file only needs to be copied to one location.

For a more detailed explanation of installing plug-ins, refer to the `Curity developer guide <https://curity.io/docs/idsvr/latest/developer-guide/plugins/index.html#plugin-installation>`_.


Configuration
~~~~~~~~~~~~~~
The authenticator has following configuration options : 

*HTTP Client* : A reference to the Http Client used to call token endpoint and userInfo endpoint.

*Authentication Context Class Reference* : The Authentication Context Class Reference (ACR) or authentication method that should be sent in the request to the OpenID Server.

*Claims* : The claims that are returned at the userInfo endpoint and in the ID token. For example - {"userinfo": {"email": null,"email_verified": null}}

*Client ID* : Client ID to be used in the authorization request sent to the Authorization/OpenID Server.

*Issuer* : URL which the OP asserts as its Issuer Identifier.

*Scope* : List of scopes requested by the client.

*Fetch User Info* : When this is toggled on, userInfo claims will be added to the Subject attributes. Only plain JSON userInfo response is supported.


License
~~~~~~~

This plugin and its associated documentation is listed under the `Apache 2 license <LICENSE>`_.

More Information
~~~~~~~~~~~~~~~~

Please visit `curity.io <https://curity.io/>`_ for more information about the Curity Identity Server.

Copyright (C) 2024 Curity AB.
