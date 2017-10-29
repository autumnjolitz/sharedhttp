Shared HTTP
--------------

Experiment in "What if I could combine `python -m http.server` with autodiscovery?"

Normal people use Dropbox for things like that. But why pay for that? Why even sign up?

Not I, the author.

Installation
---------------

If you're using OSX or Linux, you probably can just ``pip install git+https://github.com/benjolitz/sharedhttp.git``

If you're on Windows, it gets a bit more tricksy. Here's what I did to make my Windows laptop play nice:

#. Install Python3.6 for all users (Is that really necessary?)
#. Install Git into your system path (I did that a long time ago. Worth it.)
#. Open up a Command Prompt (ew!), navigate to where you make your software checkouts. (I usually use ``F:/Documents/Software``)
#. ``git clone git@github.com/channelcat/sanic.git``
#. Install the `Visual C++ 2015 Build Tools <http://landinghub.visualstudio.com/visual-cpp-build-tools>`_
#. ``set SANIC_NO_UVLOOP=true``
#. ``python -m pip install .``
#. Now installing sharedhttp will work via ``pip install git+https://github.com/benjolitz/sharedhttp.git``

Running
----------

Navigate to the directory you want to share, then type ``python -m sharedhttp``

An http server will become ready at http://localhost:8080/

If you have two machines running sharedhttp that are multicast-capable and on the same network, they should see each other and appear in the *Node Status* listing.


Screenshots
------------

Oh, I bet you're absolutely enthralled at this idea. So much that you want to see what it looks like. Well, let's not disappoint, eh?

**Bootstrapping / Waiting for Nodes**

.. image:: https://github.com/benjolitz/sharedhttp/blob/screenshots/screenshots/01bootstrap.png
    :alt: Bootstrap, no other nodes found
    :width: 835
    :align: center


**Found another node**

.. image:: https://github.com/benjolitz/sharedhttp/blob/screenshots/screenshots/02found_others.png
    :alt: Bootstrap complete, found one other node (My Windows Laptop)
    :width: 835
    :align: center

**What happens when you follow that link to the other nodes**

.. image:: https://github.com/benjolitz/sharedhttp/blob/screenshots/screenshots/03navigate_to_other.png
    :alt: Navigation to the other machine
    :width: 835
    :align: center

**Hey look, a file listing!**

.. image:: https://github.com/benjolitz/sharedhttp/blob/screenshots/screenshots/04show_other_files.png
    :alt: Showing the other node's files
    :width: 835
    :align: center

**Let's get a file**

.. image:: https://github.com/benjolitz/sharedhttp/blob/screenshots/screenshots/05getfile.png
    :alt: Getting a file
    :width: 835
    :align: center



