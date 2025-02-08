# Changes
* Adjusted the GNU flow for AU.
* Rewrote python script to receive, decrypt, decode.
* Now supports multiple keys

# Credits
[crankylinuxuser/meshtastic_sdr](https://gitlab.com/crankylinuxuser/meshtastic_sdr)

# Original
This is a GnuRadio SDR project to fully build a RX and TX stack for Meshtastic.

To run:

1. Clone repo to local machine with " git clone https://gitlab.com/crankylinuxuser/meshtastic_sdr "
2. Install Gnuradio and associated plugins.
3. Install the Meshtastic Python with "pip3 install meshtastic"
4. Clone and install https://github.com/tapparelj/gr-lora_sdr 
5. Open in ./meshtastic_sdr/gnuradio scripts/RX/ your relevant area and presets you want to monitor. RTLSDR can be used with all but the Meshtastic_US_allPresets.grc as that requires 20MHz (HackRF or better)
6. Run the flow in GnuRadio. NOTE: the flows emit data AS A server to TCP ports. Looking at the block "ZMQ PUB Sink" you can see the ports are from 20000-20007. 
7. Run the python3 program with "python3 meshtastic_gnuradio_decoder.py -n <SERVER> -p <PORT>"

The program also accepts individual packets of data with "python3 meshtastic_gnuradio_decoder.py -i <data>" 

The program also supports an optional AES key override. If you don't provide it, it uses the default 'AQ==' key.

Note that the ports are set as:
Shortfast TCP/20000
ShortSlow TCP/20001
MediumFast TCP/20002
MediumSlow TCP/20003
LongFast TCP/20004 (COMMON!)
LongModerate TCP/20005
LongSlow TCP/20006
VeryLongSlow TCP/20007


Now, why would I do this??

An SDR can decode all the presets at the same time. Real hardware can only decode the preset in which its set to.

An SDR, depending on the amount of bandwidth captured, can decode up to all of 900MHz ISM spectrum for all LoRa channels. We only need to throw CPU at the problem.

We can now RX LoRa on non-standard frequencies, like Amateur radio bands with superb propagation. Think 6M or 10M .This also depends on getting the TX flow done. Meshtastic presets do have 250KHz, 125KHz, and 62.5KHz - so this does make LoRa usable for lower bands!

Dependency: https://github.com/tapparelj/gr-lora_sdr

Note: Meshtastic is a trademark by these fine folks! https://meshtastic.org . We wouldn't be doing SDR shenanigans without'em!

![](public/US_all_preset_capture.png)