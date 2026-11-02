Building From Source
====================

In order to build dnst from the source, you need to have Rust installed on
your system, and a C toolchain and OpenSSL. The Rust compiler runs on, and
compiles to, a great number of platforms, though not all of them are equally
supported. The official `Rust Platform Support`_ page provides an overview of
the various support levels.

Prerequisites
-------------

Rust
""""

While some system distributions include Rust as system packages, dnst
relies on a relatively new version of Rust, currently |rustversion| or newer.
We therefore suggest to use the canonical Rust installation via a tool called
:program:`rustup`.

Assuming you already have :program:`curl` installed, you can install
:program:`rustup` and Rust by simply entering:

.. code-block:: text

  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

Alternatively, visit the `Rust website
<https://www.rust-lang.org/tools/install>`_ for other installation methods.

C Toolchain
"""""""""""i

Some of the libraries dnst depends on require a C toolchain to be
present. Your system probably has some easy way to install the minimum
set of packages to build from C sources. For example,
:command:`apt install build-essential` will install everything you need on
Debian/Ubuntu.

If you are unsure, try to run :command:`cc` on a command line and if there’s a
complaint about missing input files, you are probably good to go.

OpenSSL
"""""""

Your system will likely have a package manager that will allow you to install
OpenSSL in a few easy steps. For dnst, you will need :command:`libssl-dev`,
sometimes called :command:`openssl-dev`. On Debian-like Linux distributions,
this should be as simple as running:

.. code-block:: bash

    apt install libssl-dev openssl pkg-config

Building and Updating
---------------------

In Rust, a library or executable program such as dnst is called a *crate*.
Crates are normally published on `crates.io <https://crates.io/>`_, the Rust
package registry. Cargo is the Rust package manager. It is a tool that allows
Rust packages to declare their various dependencies and ensure that you’ll
always get a repeatable build. 

Cargo fetches and builds dnst’s dependencies into an executable binary for
your platform. By default you install from crates.io, but because dnst is not
yet published in the Rust package registry, you can currently only install it
directly from GitHub using the ``--git`` option. If you want to try a
specific branch, include the ``--branch`` option as well:

.. code-block:: text

    cargo install dnst --bin dnst --git https://github.com/NLnetLabs/dnst.git --branch main
    
.. Seealso:: For more installation options refer to the `Cargo book
             <https://doc.rust-lang.org/cargo/commands/cargo-install.html#install-options>`_.

Platform Specific Instructions
------------------------------

For some platforms, :program:`rustup` cannot provide binary releases to
install directly. The `Rust Platform Support`_ page lists
several platforms where official binary releases are not available, but Rust
is still guaranteed to build. For these platforms, automated tests are not
run so it’s not guaranteed to produce a working build, but they often work to
quite a good degree.

.. _Rust Platform Support:  https://doc.rust-lang.org/nightly/rustc/platform-support.html

OpenBSD
"""""""

On OpenBSD, `patches
<https://github.com/openbsd/ports/tree/master/lang/rust/patches>`_ are
required to get Rust running correctly, but these are well maintained and
offer the latest version of Rust quite quickly.

Rust can be installed on OpenBSD by running:

.. code-block:: bash

   pkg_add rust
