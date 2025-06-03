Building From Source
====================

In order to build dnst from the source, you need to have Rust installed on
your system. The Rust compiler runs on, and compiles to, a great number of
platforms, though not all of them are equally supported. The official `Rust
Platform Support`_ page provides an overview of the various support levels.

While some system distributions include Rust as system packages, Routinator
relies on a relatively new version of Rust, currently |rustversion| or newer.
We therefore suggest to use the canonical Rust installation via a tool called
:program:`rustup`.

Assuming you already have :program:`curl` installed, you can install
:program:`rustup` and Rust by simply entering:

.. code-block:: text

  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

Alternatively, visit the `Rust website
<https://www.rust-lang.org/tools/install>`_ for other installation methods.

Building and Updating
---------------------

In Rust, a library or executable program such as dnst is called a
*crate*. Crates are published on `crates.io
<https://crates.io/crates/dnst>`_, the Rust package registry. Cargo is
the Rust package manager. It is a tool that allows Rust packages to declare
their various dependencies and ensure that you’ll always get a repeatable
build. 

Cargo fetches and builds dnst’s dependencies into an executable binary
for your platform. By default you install from crates.io, but you can for
example also install from a specific Git URL, as explained below.

Installing the latest dnst release from crates.io is as simple as
running:

.. code-block:: text

  cargo install --locked dnst

The command will build dnst and install it in the same directory that
Cargo itself lives in, likely ``$HOME/.cargo/bin``. This means dnst
will be in your path, too.

Updating
""""""""

If you want to update to the latest version of dnst, it’s recommended
to update Rust itself as well, using:

.. code-block:: text

    rustup update

Use the ``--force`` option to overwrite an existing version with the latest
Routinator release:

.. code-block:: text

    cargo install --locked --force dnst

Installing Specific Versions
""""""""""""""""""""""""""""

If you want to install a specific version of
Routinator using Cargo, explicitly use the ``--version`` option. If needed,
use the ``--force`` option to overwrite an existing version:
        
.. code-block:: text

    cargo install --locked --force dnst --version 0.1.0-rc1

All new features of dnst are built on a branch and merged via a `pull
request <https://github.com/NLnetLabs/routinator/pulls>`_, allowing you to
easily try them out using Cargo. If you want to try a specific branch from
the repository you can use the ``--git`` and ``--branch`` options:

.. code-block:: text

    cargo install --git https://github.com/NLnetLabs/dnst.git --branch main
    
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
