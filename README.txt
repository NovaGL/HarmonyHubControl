HarmonyHubControl
=========

A C++ executable to control the Logitech Harmony Hub/Link without need of 
the Logitech Harmony App or Remote.

HarmonyHubControl was developed using the pyharmony library as a guide.  
It was originally written in C++ using Qt to allow simpler packaging 
than pyharmony and to reduce the number of dependencies.  Subsequently,
the Qt dependency was removed so that it is now only dependent on BSD 
sockets.

The code has been compiled and tested on both Microsoft Windows (using
Visual Studio 2010) and Ubuntu 10.0.  The code has also been cross-compiled
to OpenWRT (backfire) and tested on Vera2 and VeraLite home automation 
controllers.

HarmonyHubControl was developed particularly to ease Harmony Hub/Link 
integration within home automation systems.

Special thanks to jterrace and petele for laying down the groundwork for 
this work to occur by implementing pyharmony.



Protocol
--------

As the harmony protocol is based on xmpp (the Jabber protocol).  
A thorough description of the exchanges between the executable, Logitech's
Harmony Web service, and the Harmony Hub can be found in the included 
PROTOCOL.md file, or in the original pyharmony GitHub repositories at: 

https://github.com/jterrace/pyharmony/
and
https://github.com/petele/pyharmony/



Functionality
--------------

HarmonyHubControl provides the ability to perform the following functions
without requiring the Logitech Harmony App or Remote.

* Authenticate using Logitech's web service
* Authenticate to the local harmony device.
* Query for the harmony's entire configuration information.
* Request a list of activities and devices from the harmony
* Request the currently selected activity
* Start an activity by ID


Requirements
------------

In order to successfully use the executable, it is expected that the following
are in place:

A Harmony Hub/Link that is pre-configured and working properly on the local network
Your Logitech Harmony login email and password.  These are the same ones used in
the app or online to edit the Harmony's configuration.

The IP address of the Harmony is required.



Usage
-----

The command line for HarmonyHubControl is as follows:

    HarmonyHubControl.exe [email] [password] [harmony_ip] [command (optional)] [primary_parameter (optional)] [secondary_parameter (optional)]\n");
    
where the [email] and [password] parameters are the login credentials used to log 
into your Logitech Harmony account to update the device configuration.  These are
also the same credentials used with the Harmony app.

[harmony_ip] is the IP address of the harmony device on your network


[command] can be any of the following:

	get_current_activity_id
	list_devices
	list_activities
	start_activity [ID]
        issue_device_command [DEVICE_ID] [DEVICE_COMMAND]
	get_config


Typical example usage would be as follows:

1) Query the device for a list of activities:

	HarmonyHubControl.exe your_email@your_email_server.com your_password 192.168.0.XXX list_activities

2) Start an activity based on the activity identifiers listed in step 1:

	HarmonyHubControl.exe your_email@your_email_server.com your_password 192.168.0.XXX start_activity

For full argument information simply run the executablewith no parameters.



Building from Source
--------------------

Building the executable from source requires either Microsoft Visual Studio 2010 or Linux and gcc 
3.4.x or above.

The application has no external dependencies besides the standard libraries provided by a default 
Visual Studio or Linux gcc development environment.


To-do
--------------------

Re-organize the code into a library
