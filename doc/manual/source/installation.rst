Installation
============

Binary Packages
---------------

Getting started with dnst is really easy by installing a binary package
for either Debian and Ubuntu or for Red Hat Enterprise Linux (RHEL) and
compatible systems such as Rocky Linux. 

You can also build dnst from the source code using Cargo, Rust's build
system and package manager. Cargo lets you to run dnst on almost any
operating system and CPU architecture. Refer to the :doc:`building` section
to get started.

.. tabs::

   .. group-tab:: Debian

       To install a dnst package, you need the 64-bit version of one of
       these Debian versions:

         -  Debian Bookworm 12
         -  Debian Bullseye 11

       Packages for the ``amd64``/``x86_64`` architecture are available for
       all listed versions. In addition, we offer ``armhf`` architecture
       packages for Debian/Raspbian Bullseye, and ``arm64`` for Buster.
       
       First update the :program:`apt` package index: 

       .. code-block:: bash

          sudo apt update

       Then install packages to allow :program:`apt` to use a repository over HTTPS:

       .. code-block:: bash

          sudo apt install \
            ca-certificates \
            curl \
            gnupg \
            lsb-release

       Add the GPG key from NLnet Labs:

       .. code-block:: bash

          curl -fsSL https://packages.nlnetlabs.nl/aptkey.asc | sudo gpg --dearmor -o /usr/share/keyrings/nlnetlabs-archive-keyring.gpg

       Now, use the following command to set up the *main* repository:

       .. code-block:: bash

          echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/nlnetlabs-archive-keyring.gpg] https://packages.nlnetlabs.nl/linux/debian \
          $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/nlnetlabs.list > /dev/null

       Update the :program:`apt` package index once more: 

       .. code-block:: bash

          sudo apt update

       You can now install dnst with:

       .. code-block:: bash

          sudo apt install dnst

   .. group-tab:: Ubuntu

       To install a dnst package, you need the 64-bit version of one of
       these Ubuntu versions:

         - Ubuntu Noble 24.04 (LTS)
         - Ubuntu Jammy 22.04 (LTS)
         - Ubuntu Focal 20.04 (LTS)

       Packages are available for the ``amd64``/``x86_64`` architecture only.
       
       First update the :program:`apt` package index: 

       .. code-block:: bash

          sudo apt update

       Then install packages to allow :program:`apt` to use a repository over HTTPS:

       .. code-block:: bash

          sudo apt install \
            ca-certificates \
            curl \
            gnupg \
            lsb-release

       Add the GPG key from NLnet Labs:

       .. code-block:: bash

          curl -fsSL https://packages.nlnetlabs.nl/aptkey.asc | sudo gpg --dearmor -o /usr/share/keyrings/nlnetlabs-archive-keyring.gpg

       Now, use the following command to set up the *main* repository:

       .. code-block:: bash

          echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/nlnetlabs-archive-keyring.gpg] https://packages.nlnetlabs.nl/linux/ubuntu \
          $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/nlnetlabs.list > /dev/null

       Update the :program:`apt` package index once more: 

       .. code-block:: bash

          sudo apt update

       You can now install dnst with:

       .. code-block:: bash

          sudo apt install dnst

   .. group-tab:: RHEL

       To install a dnst package, you need Red Hat Enterprise Linux
       (RHEL) 8 or 9, or compatible operating system such as Rocky Linux.
       Packages are available for the ``amd64``/``x86_64`` architecture only.
       
       First create a file named :file:`/etc/yum.repos.d/nlnetlabs.repo`,
       enter this configuration and save it:
       
       .. code-block:: text
       
          [nlnetlabs]
          name=NLnet Labs
          baseurl=https://packages.nlnetlabs.nl/linux/centos/$releasever/main/$basearch
          enabled=1
        
       Add the GPG key from NLnet Labs:
       
       .. code-block:: bash
       
          sudo rpm --import https://packages.nlnetlabs.nl/aptkey.asc
       
       You can now install dnst with:

       .. code-block:: bash

          sudo yum install -y dnst

Updating
--------

.. tabs::

   .. group-tab:: Debian

       To update an existing dnst installation, first update the 
       repository using:

       .. code-block:: text

          sudo apt update

       You can use this command to get an overview of the available versions:

       .. code-block:: text

          sudo apt policy dnst

       You can upgrade an existing dnst installation to the latest
       version using:

       .. code-block:: text

          sudo apt --only-upgrade install dnst

   .. group-tab:: Ubuntu

       To update an existing dnst installation, first update the 
       repository using:

       .. code-block:: text

          sudo apt update

       You can use this command to get an overview of the available versions:

       .. code-block:: text

          sudo apt policy dnst

       You can upgrade an existing dnst installation to the latest
       version using:

       .. code-block:: text

          sudo apt --only-upgrade install dnst

   .. group-tab:: RHEL

       To update an existing dnst installation, you can use this
       command to get an overview of the available versions:
        
       .. code-block:: bash
        
          sudo yum --showduplicates list dnst
          
       You can update to the latest version using:
         
       .. code-block:: bash
         
          sudo yum update -y dnst

Installing Specific Versions
----------------------------

Before every new release of dnst, one or more release candidates are 
provided for testing through every installation method. You can also install
a specific version, if needed.

.. tabs::

   .. group-tab:: Debian

       If you would like to try out release candidates of dnst you can
       add the *proposed* repository to the existing *main* repository
       described earlier. 
       
       Assuming you already have followed the steps to install regular releases,
       run this command to add the additional repository:

       .. code-block:: bash

          echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/nlnetlabs-archive-keyring.gpg] https://packages.nlnetlabs.nl/linux/debian \
          $(lsb_release -cs)-proposed main" | sudo tee /etc/apt/sources.list.d/nlnetlabs-proposed.list > /dev/null

       Make sure to update the :program:`apt` package index:

       .. code-block:: bash

          sudo apt update
       
       You can now use this command to get an overview of the available 
       versions:

       .. code-block:: bash

          sudo apt policy dnst

       You can install a specific version using ``<package name>=<version>``,
       e.g.:

       .. code-block:: bash

          sudo apt install dnst=0.1.0~rc1-1bookworm

   .. group-tab:: Ubuntu

       If you would like to try out release candidates of dnst you can
       add the *proposed* repository to the existing *main* repository
       described earlier. 
       
       Assuming you already have followed the steps to install regular
       releases, run this command to add the additional repository:

       .. code-block:: bash

          echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/nlnetlabs-archive-keyring.gpg] https://packages.nlnetlabs.nl/linux/ubuntu \
          $(lsb_release -cs)-proposed main" | sudo tee /etc/apt/sources.list.d/nlnetlabs-proposed.list > /dev/null

       Make sure to update the :program:`apt` package index:

       .. code-block:: bash

          sudo apt update
       
       You can now use this command to get an overview of the available 
       versions:

       .. code-block:: bash

          sudo apt policy dnst

       You can install a specific version using ``<package name>=<version>``,
       e.g.:

       .. code-block:: bash

          sudo apt install dnst=0.1.0~rc1-1jammy
          
   .. group-tab:: RHEL

       To install release candidates of dnst, create an additional repo 
       file named :file:`/etc/yum.repos.d/nlnetlabs-testing.repo`, enter this
       configuration and save it:
       
       .. code-block:: text
       
          [nlnetlabs-testing]
          name=NLnet Labs Testing
          baseurl=https://packages.nlnetlabs.nl/linux/centos/$releasever/proposed/$basearch
          enabled=1
        
       You can use this command to get an overview of the available versions:
        
       .. code-block:: bash
        
          sudo yum --showduplicates list dnst
          
       You can install a specific version using 
       ``<package name>-<version info>``, e.g.:
         
       .. code-block:: bash
         
          sudo yum install -y dnst-0.1.0~rc1

               
