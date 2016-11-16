# In-band telemetry for VNFs in P4

A core strength of P4 is its ability to define new data plane protocols. This lab demonstrates how this capability is leveraged to implement In-band Network Telemetry (INT) for transparently capturing latency statistics for any TCP based packet forwarding Virtual Network Function (VNF). Participants will see how to declaratively define a TCP option to store ingress timestamp metadata within packets destined to the VNF while maintaining L4 checksums within the Agilio SmartNIC. A mock-up of the VNF hosted in a virtual machine serves as an example so that participants can inspect and verify that the incoming traffic comprises valid TCP packets containing the optional INT header extension. This INT header is later extracted by the P4 pipeline at egress before being removed so that pristine packets are sent on to the attached network. Extending the P4 pipeline capabilities with C code that calculates and logs the desired latency statistics is also shown.

# Prerequisites

1. An installation of Netronome's Programmer Studio P4 Integrated Development Environment (available from [link](http://open-nfp.org)).
2. Access to a Linux server having a Netronome Agilio SmartNIC installed with its supporting board support utilities.

# Getting Started 

1. Download the source code.
2. Follow the instructions in the workbook.
